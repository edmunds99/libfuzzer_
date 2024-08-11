//===- FuzzerLoop.cpp - Fuzzer's main loop --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// Fuzzer's main loop.
//===----------------------------------------------------------------------===//

#include "FuzzerCorpus.h"
#include "FuzzerIO.h"
#include "FuzzerInternal.h"
#include "FuzzerMutate.h"
#include "FuzzerPlatform.h"
#include "FuzzerRandom.h"
#include "FuzzerTracePC.h"
// #include "FSM_new.h"
#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <set>

#if defined(__has_include)
#if __has_include(<sanitizer / lsan_interface.h>)
#include <sanitizer/lsan_interface.h>
#endif
#endif

#define NO_SANITIZE_MEMORY
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#undef NO_SANITIZE_MEMORY
#define NO_SANITIZE_MEMORY __attribute__((no_sanitize_memory))
#endif
#endif

namespace fuzzer {
static const size_t kMaxUnitSizeToPrint = 256;

thread_local bool Fuzzer::IsMyThread;

bool RunningUserCallback = false;

// const int max_state_num=100;   // defined in FuzzerDefs.h
const int max_state_exec=1000;
int first_runs=1000000;
int fixed_consume_size=9;   // is_br + is_initiator + is_peripheral + io_req
int state_cov_interval=30;
size_t last_cov=0;
size_t cur_cov;
system_clock::time_point last_cov_upd;
uint8_t m1_m2_sep=250;
int state_exec_times[max_state_num+5];
bool state_executed[max_state_num+5];
State cur_state;

// Only one Fuzzer per process.
static Fuzzer *F;

// Leak detection is expensive, so we first check if there were more mallocs
// than frees (using the sanitizer malloc hooks) and only then try to call lsan.
struct MallocFreeTracer {
  void Start(int TraceLevel) {
    this->TraceLevel = TraceLevel;
    if (TraceLevel)
      Printf("MallocFreeTracer: START\n");
    Mallocs = 0;
    Frees = 0;
  }
  // Returns true if there were more mallocs than frees.
  bool Stop() {
    if (TraceLevel)
      Printf("MallocFreeTracer: STOP %zd %zd (%s)\n", Mallocs.load(),
             Frees.load(), Mallocs == Frees ? "same" : "DIFFERENT");
    bool Result = Mallocs > Frees;
    Mallocs = 0;
    Frees = 0;
    TraceLevel = 0;
    return Result;
  }
  std::atomic<size_t> Mallocs;
  std::atomic<size_t> Frees;
  int TraceLevel = 0;

  std::recursive_mutex TraceMutex;
  bool TraceDisabled = false;
};

static MallocFreeTracer AllocTracer;

// Locks printing and avoids nested hooks triggered from mallocs/frees in
// sanitizer.
class TraceLock {
public:
  TraceLock() : Lock(AllocTracer.TraceMutex) {
    AllocTracer.TraceDisabled = !AllocTracer.TraceDisabled;
  }
  ~TraceLock() { AllocTracer.TraceDisabled = !AllocTracer.TraceDisabled; }

  bool IsDisabled() const {
    // This is already inverted value.
    return !AllocTracer.TraceDisabled;
  }

private:
  std::lock_guard<std::recursive_mutex> Lock;
};

ATTRIBUTE_NO_SANITIZE_MEMORY
void MallocHook(const volatile void *ptr, size_t size) {
  size_t N = AllocTracer.Mallocs++;
  F->HandleMalloc(size);
  if (int TraceLevel = AllocTracer.TraceLevel) {
    TraceLock Lock;
    if (Lock.IsDisabled())
      return;
    Printf("MALLOC[%zd] %p %zd\n", N, ptr, size);
    if (TraceLevel >= 2 && EF)
      PrintStackTrace();
  }
}

ATTRIBUTE_NO_SANITIZE_MEMORY
void FreeHook(const volatile void *ptr) {
  size_t N = AllocTracer.Frees++;
  if (int TraceLevel = AllocTracer.TraceLevel) {
    TraceLock Lock;
    if (Lock.IsDisabled())
      return;
    Printf("FREE[%zd]   %p\n", N, ptr);
    if (TraceLevel >= 2 && EF)
      PrintStackTrace();
  }
}

// Crash on a single malloc that exceeds the rss limit.
void Fuzzer::HandleMalloc(size_t Size) {
  if (!Options.MallocLimitMb || (Size >> 20) < (size_t)Options.MallocLimitMb)
    return;
  Printf("==%d== ERROR: libFuzzer: out-of-memory (malloc(%zd))\n", GetPid(),
         Size);
  Printf("   To change the out-of-memory limit use -rss_limit_mb=<N>\n\n");
  PrintStackTrace();
  DumpCurrentUnit("oom-");
  Printf("SUMMARY: libFuzzer: out-of-memory\n");
  PrintFinalStats();
  _Exit(Options.OOMExitCode); // Stop right now.
}

Fuzzer::Fuzzer(UserCallback CB, InputCorpus &Corpus, MutationDispatcher &MD,
               FuzzingOptions Options)
    : CB(CB), Corpus(Corpus), MD(MD), Options(Options) {

  std::string fake_state_corpus_dir="";
  struct EntropicOptions fake_entropic;
  fake_entropic.Enabled = Options.Entropic;
  fake_entropic.FeatureFrequencyThreshold =
      Options.EntropicFeatureFrequencyThreshold;
  fake_entropic.NumberOfRarestFeatures = Options.EntropicNumberOfRarestFeatures;
  fake_entropic.ScalePerExecTime = Options.EntropicScalePerExecTime;
  for (int i=0; i<max_state_num; i++)
    state_corpus[i].initialize(fake_state_corpus_dir, fake_entropic);
    
  if (EF->__sanitizer_set_death_callback)
    EF->__sanitizer_set_death_callback(StaticDeathCallback);
  assert(!F);
  F = this;
  TPC.ResetMaps();
  IsMyThread = true;
  if (Options.DetectLeaks && EF->__sanitizer_install_malloc_and_free_hooks)
    EF->__sanitizer_install_malloc_and_free_hooks(MallocHook, FreeHook);
  TPC.SetUseCounters(Options.UseCounters);
  TPC.SetUseValueProfileMask(Options.UseValueProfile);

  if (Options.Verbosity)
    TPC.PrintModuleInfo();
  if (!Options.OutputCorpus.empty() && Options.ReloadIntervalSec)
    EpochOfLastReadOfOutputCorpus = GetEpoch(Options.OutputCorpus);
  MaxInputLen = MaxMutationLen = Options.MaxLen;
  TmpMaxMutationLen = 0;  // Will be set once we load the corpus.
  AllocateCurrentUnitData();
  CurrentUnitSize = 0;
  memset(BaseSha1, 0, sizeof(BaseSha1));
}

Fuzzer::~Fuzzer() {}

void Fuzzer::AllocateCurrentUnitData() {
  if (CurrentUnitData || MaxInputLen == 0)
    return;
  CurrentUnitData = new uint8_t[MaxInputLen];
}

void Fuzzer::StaticDeathCallback() {
  assert(F);
  F->DeathCallback();
}

void Fuzzer::DumpCurrentUnit(const char *Prefix) {
  if (!CurrentUnitData)
    return; // Happens when running individual inputs.
  ScopedDisableMsanInterceptorChecks S;
  MD.PrintMutationSequence();
  Printf("; base unit: %s\n", Sha1ToString(BaseSha1).c_str());
  size_t UnitSize = CurrentUnitSize;
  if (UnitSize <= kMaxUnitSizeToPrint) {
    PrintHexArray(CurrentUnitData, UnitSize, "\n");
    PrintASCII(CurrentUnitData, UnitSize, "\n");
  }
  WriteUnitToFileWithPrefix({CurrentUnitData, CurrentUnitData + UnitSize},
                            Prefix);
}

NO_SANITIZE_MEMORY
void Fuzzer::DeathCallback() {
  DumpCurrentUnit("crash-");
  PrintFinalStats();
}

void Fuzzer::StaticAlarmCallback() {
  assert(F);
  F->AlarmCallback();
}

void Fuzzer::StaticCrashSignalCallback() {
  assert(F);
  F->CrashCallback();
}

void Fuzzer::StaticExitCallback() {
  assert(F);
  F->ExitCallback();
}

void Fuzzer::StaticInterruptCallback() {
  assert(F);
  F->InterruptCallback();
}

void Fuzzer::StaticGracefulExitCallback() {
  assert(F);
  F->GracefulExitRequested = true;
  Printf("INFO: signal received, trying to exit gracefully\n");
}

void Fuzzer::StaticFileSizeExceedCallback() {
  Printf("==%lu== ERROR: libFuzzer: file size exceeded\n", GetPid());
  exit(1);
}

void Fuzzer::CrashCallback() {
  if (EF->__sanitizer_acquire_crash_state &&
      !EF->__sanitizer_acquire_crash_state())
    return;
  Printf("==%lu== ERROR: libFuzzer: deadly signal\n", GetPid());
  PrintStackTrace();
  Printf("NOTE: libFuzzer has rudimentary signal handlers.\n"
         "      Combine libFuzzer with AddressSanitizer or similar for better "
         "crash reports.\n");
  Printf("SUMMARY: libFuzzer: deadly signal\n");
  DumpCurrentUnit("crash-");
  PrintFinalStats();
  _Exit(Options.ErrorExitCode); // Stop right now.
}

void Fuzzer::ExitCallback() {
  if (!RunningUserCallback)
    return; // This exit did not come from the user callback
  if (EF->__sanitizer_acquire_crash_state &&
      !EF->__sanitizer_acquire_crash_state())
    return;
  Printf("==%lu== ERROR: libFuzzer: fuzz target exited\n", GetPid());
  PrintStackTrace();
  Printf("SUMMARY: libFuzzer: fuzz target exited\n");
  DumpCurrentUnit("crash-");
  PrintFinalStats();
  _Exit(Options.ErrorExitCode);
}

void Fuzzer::MaybeExitGracefully() {
  if (!F->GracefulExitRequested) return;
  Printf("==%lu== INFO: libFuzzer: exiting as requested\n", GetPid());
  RmDirRecursive(TempPath("FuzzWithFork", ".dir"));
  F->PrintFinalStats();
  _Exit(0);
}

void Fuzzer::InterruptCallback() {
  Printf("==%lu== libFuzzer: run interrupted; exiting\n", GetPid());
  PrintFinalStats();
  ScopedDisableMsanInterceptorChecks S; // RmDirRecursive may call opendir().
  RmDirRecursive(TempPath("FuzzWithFork", ".dir"));
  // Stop right now, don't perform any at-exit actions.
  _Exit(Options.InterruptExitCode);
}

NO_SANITIZE_MEMORY
void Fuzzer::AlarmCallback() {
  assert(Options.UnitTimeoutSec > 0);
  // In Windows and Fuchsia, Alarm callback is executed by a different thread.
  // NetBSD's current behavior needs this change too.
#if !LIBFUZZER_WINDOWS && !LIBFUZZER_NETBSD && !LIBFUZZER_FUCHSIA
  if (!InFuzzingThread())
    return;
#endif
  if (!RunningUserCallback)
    return; // We have not started running units yet.
  size_t Seconds =
      duration_cast<seconds>(system_clock::now() - UnitStartTime).count();
  if (Seconds == 0)
    return;
  if (Options.Verbosity >= 2)
    Printf("AlarmCallback %zd\n", Seconds);
  if (Seconds >= (size_t)Options.UnitTimeoutSec) {
    if (EF->__sanitizer_acquire_crash_state &&
        !EF->__sanitizer_acquire_crash_state())
      return;
    Printf("ALARM: working on the last Unit for %zd seconds\n", Seconds);
    Printf("       and the timeout value is %d (use -timeout=N to change)\n",
           Options.UnitTimeoutSec);
    DumpCurrentUnit("timeout-");
    Printf("==%lu== ERROR: libFuzzer: timeout after %d seconds\n", GetPid(),
           Seconds);
    PrintStackTrace();
    Printf("SUMMARY: libFuzzer: timeout\n");
    PrintFinalStats();
    _Exit(Options.TimeoutExitCode); // Stop right now.
  }
}

void Fuzzer::RssLimitCallback() {
  if (EF->__sanitizer_acquire_crash_state &&
      !EF->__sanitizer_acquire_crash_state())
    return;
  Printf(
      "==%lu== ERROR: libFuzzer: out-of-memory (used: %zdMb; limit: %zdMb)\n",
      GetPid(), GetPeakRSSMb(), Options.RssLimitMb);
  Printf("   To change the out-of-memory limit use -rss_limit_mb=<N>\n\n");
  PrintMemoryProfile();
  DumpCurrentUnit("oom-");
  Printf("SUMMARY: libFuzzer: out-of-memory\n");
  PrintFinalStats();
  _Exit(Options.OOMExitCode); // Stop right now.
}

void Fuzzer::PrintStats(const char *Where, const char *End, size_t Units,
                        size_t Features) {
  size_t ExecPerSec = execPerSec();
  if (!Options.Verbosity)
    return;
  Printf("#%zd\t%s", TotalNumberOfRuns, Where);
  if (size_t N = TPC.GetTotalPCCoverage())
    Printf(" cov: %zd", N);
  if (size_t N = Features ? Features : Corpus.NumFeatures())
    Printf(" ft: %zd", N);
  if (!Corpus.empty()) {
    Printf(" corp: %zd", Corpus.NumActiveUnits());
    if (size_t N = Corpus.SizeInBytes()) {
      if (N < (1 << 14))
        Printf("/%zdb", N);
      else if (N < (1 << 24))
        Printf("/%zdKb", N >> 10);
      else
        Printf("/%zdMb", N >> 20);
    }
    if (size_t FF = Corpus.NumInputsThatTouchFocusFunction())
      Printf(" focus: %zd", FF);
  }
  if (TmpMaxMutationLen)
    Printf(" lim: %zd", TmpMaxMutationLen);
  if (Units)
    Printf(" units: %zd", Units);

  Printf(" exec/s: %zd", ExecPerSec);
  Printf(" rss: %zdMb", GetPeakRSSMb());
  Printf("%s", End);
}

void Fuzzer::PrintFinalStats() {
  if (Options.PrintFullCoverage)
    TPC.PrintCoverage(/*PrintAllCounters=*/true);
  if (Options.PrintCoverage)
    TPC.PrintCoverage(/*PrintAllCounters=*/false);
  if (Options.PrintCorpusStats)
    Corpus.PrintStats();
  if (!Options.PrintFinalStats)
    return;
  size_t ExecPerSec = execPerSec();
  Printf("stat::number_of_executed_units: %zd\n", TotalNumberOfRuns);
  Printf("stat::average_exec_per_sec:     %zd\n", ExecPerSec);
  Printf("stat::new_units_added:          %zd\n", NumberOfNewUnitsAdded);
  Printf("stat::slowest_unit_time_sec:    %zd\n", TimeOfLongestUnitInSeconds);
  Printf("stat::peak_rss_mb:              %zd\n", GetPeakRSSMb());
}

void Fuzzer::SetMaxInputLen(size_t MaxInputLen) {
  assert(this->MaxInputLen == 0); // Can only reset MaxInputLen from 0 to non-0.
  assert(MaxInputLen);
  this->MaxInputLen = MaxInputLen;
  this->MaxMutationLen = MaxInputLen;
  AllocateCurrentUnitData();
  Printf("INFO: -max_len is not provided; "
         "libFuzzer will not generate inputs larger than %zd bytes\n",
         MaxInputLen);
}

void Fuzzer::SetMaxMutationLen(size_t MaxMutationLen) {
  assert(MaxMutationLen && MaxMutationLen <= MaxInputLen);
  this->MaxMutationLen = MaxMutationLen;
}

void Fuzzer::CheckExitOnSrcPosOrItem() {
  if (!Options.ExitOnSrcPos.empty()) {
    static auto *PCsSet = new Set<uintptr_t>;
    auto HandlePC = [&](const TracePC::PCTableEntry *TE) {
      if (!PCsSet->insert(TE->PC).second)
        return;
      std::string Descr = DescribePC("%F %L", TE->PC + 1);
      if (Descr.find(Options.ExitOnSrcPos) != std::string::npos) {
        Printf("INFO: found line matching '%s', exiting.\n",
               Options.ExitOnSrcPos.c_str());
        _Exit(0);
      }
    };
    TPC.ForEachObservedPC(HandlePC);
  }
  if (!Options.ExitOnItem.empty()) {
    if (Corpus.HasUnit(Options.ExitOnItem)) {
      Printf("INFO: found item with checksum '%s', exiting.\n",
             Options.ExitOnItem.c_str());
      _Exit(0);
    }
  }
}

void Fuzzer::RereadOutputCorpus(size_t MaxSize) {
  if (Options.OutputCorpus.empty() || !Options.ReloadIntervalSec)
    return;
  Vector<Unit> AdditionalCorpus;
  Vector<std::string> AdditionalCorpusPaths;
  ReadDirToVectorOfUnits(
      Options.OutputCorpus.c_str(), &AdditionalCorpus,
      &EpochOfLastReadOfOutputCorpus, MaxSize,
      /*ExitOnError*/ false,
      (Options.Verbosity >= 2 ? &AdditionalCorpusPaths : nullptr));
  if (Options.Verbosity >= 2)
    Printf("Reload: read %zd new units.\n", AdditionalCorpus.size());
  bool Reloaded = false;
  for (size_t i = 0; i != AdditionalCorpus.size(); ++i) {
    auto &U = AdditionalCorpus[i];
    if (U.size() > MaxSize)
      U.resize(MaxSize);
    if (!Corpus.HasUnit(U)) {
      if (RunOne(U.data(), U.size())) {          // note: re-run the output corpus
        CheckExitOnSrcPosOrItem();
        Reloaded = true;
        if (Options.Verbosity >= 2)
          Printf("Reloaded %s\n", AdditionalCorpusPaths[i].c_str());
      }
    }
  }
  if (Reloaded)
    PrintStats("RELOAD");
}

void Fuzzer::PrintPulseAndReportSlowInput(const uint8_t *Data, size_t Size) {
  auto TimeOfUnit =
      duration_cast<seconds>(UnitStopTime - UnitStartTime).count();
  if (!(TotalNumberOfRuns & (TotalNumberOfRuns - 1)) &&
      secondsSinceProcessStartUp() >= 2)
    PrintStats("pulse ");
  auto Threshhold =
      static_cast<long>(static_cast<double>(TimeOfLongestUnitInSeconds) * 1.1);
  if (TimeOfUnit > Threshhold && TimeOfUnit >= Options.ReportSlowUnits) {
    TimeOfLongestUnitInSeconds = TimeOfUnit;
    Printf("Slowest unit: %zd s:\n", TimeOfLongestUnitInSeconds);
    WriteUnitToFileWithPrefix({Data, Data + Size}, "slow-unit-");
  }
}

static void WriteFeatureSetToFile(const std::string &FeaturesDir,
                                  const std::string &FileName,
                                  const Vector<uint32_t> &FeatureSet) {
  if (FeaturesDir.empty() || FeatureSet.empty()) return;
  WriteToFile(reinterpret_cast<const uint8_t *>(FeatureSet.data()),
              FeatureSet.size() * sizeof(FeatureSet[0]),
              DirPlusFile(FeaturesDir, FileName));
}

static void RenameFeatureSetFile(const std::string &FeaturesDir,
                                 const std::string &OldFile,
                                 const std::string &NewFile) {
  if (FeaturesDir.empty()) return;
  RenameFile(DirPlusFile(FeaturesDir, OldFile),
             DirPlusFile(FeaturesDir, NewFile));
}

static void WriteEdgeToMutationGraphFile(const std::string &MutationGraphFile,
                                         const InputInfo *II,
                                         const InputInfo *BaseII,
                                         const std::string &MS) {
  if (MutationGraphFile.empty())
    return;

  std::string Sha1 = Sha1ToString(II->Sha1);

  std::string OutputString;

  // Add a new vertex.
  OutputString.append("\"");
  OutputString.append(Sha1);
  OutputString.append("\"\n");

  // Add a new edge if there is base input.
  if (BaseII) {
    std::string BaseSha1 = Sha1ToString(BaseII->Sha1);
    OutputString.append("\"");
    OutputString.append(BaseSha1);
    OutputString.append("\" -> \"");
    OutputString.append(Sha1);
    OutputString.append("\" [label=\"");
    OutputString.append(MS);
    OutputString.append("\"];\n");
  }

  AppendToFile(OutputString, MutationGraphFile);
}

bool Fuzzer::RunOne(const uint8_t *Data, size_t Size, bool MayDeleteFile,
                    InputInfo *II, bool ForceAddToCorpus,
                    bool *FoundUniqFeatures) {
  if (!Size)
    return false;
  // Largest input length should be INT_MAX.
  assert(Size < std::numeric_limits<uint32_t>::max());

  ExecuteCallback(Data, Size);      // note: execute (self defined) Fuzz
  state_exec_times[cur_state.id]++; 
  auto TimeOfUnit = duration_cast<microseconds>(UnitStopTime - UnitStartTime);

  UniqFeatureSetTmp.clear();
  size_t FoundUniqFeaturesOfII = 0;
  size_t NumUpdatesBefore = Corpus.NumFeatureUpdates();
  TPC.CollectFeatures([&](uint32_t Feature) {
    if (Corpus.AddFeature(Feature, static_cast<uint32_t>(Size), Options.Shrink))
      UniqFeatureSetTmp.push_back(Feature);
    state_corpus[cur_state.id].AddFeature(Feature, static_cast<uint32_t>(Size), Options.Shrink);  // newly added
    
    if (Options.Entropic) {
      Corpus.UpdateFeatureFrequency(II, Feature);
      state_corpus[cur_state.id].UpdateFeatureFrequency(II, Feature);   // newly added
    }
    if (Options.ReduceInputs && II && !II->NeverReduce)
      if (std::binary_search(II->UniqFeatureSet.begin(),
                             II->UniqFeatureSet.end(), Feature))
        FoundUniqFeaturesOfII++;
  });

  if (FoundUniqFeatures)
    *FoundUniqFeatures = FoundUniqFeaturesOfII;
  PrintPulseAndReportSlowInput(Data, Size);
  size_t NumNewFeatures = Corpus.NumFeatureUpdates() - NumUpdatesBefore;
  if (NumNewFeatures || ForceAddToCorpus) {
    TPC.UpdateObservedPCs();
    auto NewII =
        Corpus.AddToCorpus({Data, Data + Size}, NumNewFeatures, MayDeleteFile,
                           TPC.ObservedFocusFunction(), ForceAddToCorpus,
                           TimeOfUnit, UniqFeatureSetTmp, DFT, II);      // note: add to corpus
    auto state_NewII =
        state_corpus[cur_state.id].AddToCorpus({Data, Data + Size}, NumNewFeatures, MayDeleteFile,
                           TPC.ObservedFocusFunction(), ForceAddToCorpus,
                           TimeOfUnit, UniqFeatureSetTmp, DFT, II);      
                           // newly added. add to state_corpus

    WriteFeatureSetToFile(Options.FeaturesDir, Sha1ToString(NewII->Sha1),
                          NewII->UniqFeatureSet);
    WriteEdgeToMutationGraphFile(Options.MutationGraphFile, NewII, II,
                                 MD.MutationSequence());
    return true;
  }

  if (II && FoundUniqFeaturesOfII &&
      II->DataFlowTraceForFocusFunction.empty() &&
      FoundUniqFeaturesOfII == II->UniqFeatureSet.size() &&
      II->U.size() > Size) {
    auto OldFeaturesFile = Sha1ToString(II->Sha1);
    Corpus.Replace(II, {Data, Data + Size});
    state_corpus[cur_state.id].Replace(II, {Data, Data + Size});   // newly added
    // Printf("state corpus replace success 590\n");
    RenameFeatureSetFile(Options.FeaturesDir, OldFeaturesFile,
                         Sha1ToString(II->Sha1));
    return true;
  }
  return false;
}

void Fuzzer::TPCUpdateObservedPCs() { TPC.UpdateObservedPCs(); }

size_t Fuzzer::GetCurrentUnitInFuzzingThead(const uint8_t **Data) const {
  assert(InFuzzingThread());
  *Data = CurrentUnitData;
  return CurrentUnitSize;
}

void Fuzzer::CrashOnOverwrittenData() {
  Printf("==%d== ERROR: libFuzzer: fuzz target overwrites its const input\n",
         GetPid());
  PrintStackTrace();
  Printf("SUMMARY: libFuzzer: overwrites-const-input\n");
  DumpCurrentUnit("crash-");
  PrintFinalStats();
  _Exit(Options.ErrorExitCode); // Stop right now.
}

// Compare two arrays, but not all bytes if the arrays are large.
static bool LooseMemeq(const uint8_t *A, const uint8_t *B, size_t Size) {
  const size_t Limit = 64;
  if (Size <= 64)
    return !memcmp(A, B, Size);
  // Compare first and last Limit/2 bytes.
  return !memcmp(A, B, Limit / 2) &&
         !memcmp(A + Size - Limit / 2, B + Size - Limit / 2, Limit / 2);
}

// This method is not inlined because it would cause a test to fail where it
// is part of the stack unwinding. See D97975 for details.
ATTRIBUTE_NOINLINE void Fuzzer::ExecuteCallback(const uint8_t *Data,
                                                size_t Size) {
  TPC.RecordInitialStack();
  TotalNumberOfRuns++;
  assert(InFuzzingThread());
  // We copy the contents of Unit into a separate heap buffer
  // so that we reliably find buffer overflows in it.
  uint8_t *DataCopy = new uint8_t[Size];
  memcpy(DataCopy, Data, Size);
  if (EF->__msan_unpoison)
    EF->__msan_unpoison(DataCopy, Size);
  if (EF->__msan_unpoison_param)
    EF->__msan_unpoison_param(2);
  if (CurrentUnitData && CurrentUnitData != Data)
    memcpy(CurrentUnitData, Data, Size);
  CurrentUnitSize = Size;
  {
    ScopedEnableMsanInterceptorChecks S;
    AllocTracer.Start(Options.TraceMalloc);
    UnitStartTime = system_clock::now();
    TPC.ResetMaps();
    RunningUserCallback = true;
    int Res = CB(DataCopy, Size);
    RunningUserCallback = false;
    UnitStopTime = system_clock::now();
    (void)Res;
    assert(Res == 0);
    HasMoreMallocsThanFrees = AllocTracer.Stop();
  }
  if (!LooseMemeq(DataCopy, Data, Size))
    CrashOnOverwrittenData();
  CurrentUnitSize = 0;
  delete[] DataCopy;
}

std::string Fuzzer::WriteToOutputCorpus(const Unit &U) {
  if (Options.OnlyASCII)
    assert(IsASCII(U));
  if (Options.OutputCorpus.empty())
    return "";
  std::string Path = DirPlusFile(Options.OutputCorpus, Hash(U));
  WriteToFile(U, Path);
  if (Options.Verbosity >= 2)
    Printf("Written %zd bytes to %s\n", U.size(), Path.c_str());
  return Path;
}

void Fuzzer::WriteUnitToFileWithPrefix(const Unit &U, const char *Prefix) {
  if (!Options.SaveArtifacts)
    return;
  std::string Path = Options.ArtifactPrefix + Prefix + Hash(U);
  if (!Options.ExactArtifactPath.empty())
    Path = Options.ExactArtifactPath; // Overrides ArtifactPrefix.
  WriteToFile(U, Path);
  Printf("artifact_prefix='%s'; Test unit written to %s\n",
         Options.ArtifactPrefix.c_str(), Path.c_str());
  if (U.size() <= kMaxUnitSizeToPrint)
    Printf("Base64: %s\n", Base64(U).c_str());
}

void Fuzzer::PrintStatusForNewUnit(const Unit &U, const char *Text) {
  if (!Options.PrintNEW)
    return;
  PrintStats(Text, "");
  if (Options.Verbosity) {
    Printf(" L: %zd/%zd ", U.size(), Corpus.MaxInputSize());
    MD.PrintMutationSequence(Options.Verbosity >= 2);
    Printf("\n");
  }
}

void Fuzzer::ReportNewCoverage(InputInfo *II, const Unit &U) {
  II->NumSuccessfullMutations++;
  MD.RecordSuccessfulMutationSequence();
  PrintStatusForNewUnit(U, II->Reduced ? "REDUCE" : "NEW   ");

  WriteToOutputCorpus(U);    // note: save to corpus (in output dir)

  NumberOfNewUnitsAdded++;
  CheckExitOnSrcPosOrItem(); // Check only after the unit is saved to corpus.
  LastCorpusUpdateRun = TotalNumberOfRuns;
}

// Tries detecting a memory leak on the particular input that we have just
// executed before calling this function.
void Fuzzer::TryDetectingAMemoryLeak(const uint8_t *Data, size_t Size,
                                     bool DuringInitialCorpusExecution) {
  if (!HasMoreMallocsThanFrees)
    return; // mallocs==frees, a leak is unlikely.
  if (!Options.DetectLeaks)
    return;
  if (!DuringInitialCorpusExecution &&
      TotalNumberOfRuns >= Options.MaxNumberOfRuns)
    return;
  if (!&(EF->__lsan_enable) || !&(EF->__lsan_disable) ||
      !(EF->__lsan_do_recoverable_leak_check))
    return; // No lsan.
  // Run the target once again, but with lsan disabled so that if there is
  // a real leak we do not report it twice.
  EF->__lsan_disable();
  ExecuteCallback(Data, Size);
  EF->__lsan_enable();
  if (!HasMoreMallocsThanFrees)
    return; // a leak is unlikely.
  if (NumberOfLeakDetectionAttempts++ > 1000) {
    Options.DetectLeaks = false;
    Printf("INFO: libFuzzer disabled leak detection after every mutation.\n"
           "      Most likely the target function accumulates allocated\n"
           "      memory in a global state w/o actually leaking it.\n"
           "      You may try running this binary with -trace_malloc=[12]"
           "      to get a trace of mallocs and frees.\n"
           "      If LeakSanitizer is enabled in this process it will still\n"
           "      run on the process shutdown.\n");
    return;
  }
  // Now perform the actual lsan pass. This is expensive and we must ensure
  // we don't call it too often.
  if (EF->__lsan_do_recoverable_leak_check()) { // Leak is found, report it.
    if (DuringInitialCorpusExecution)
      Printf("\nINFO: a leak has been found in the initial corpus.\n\n");
    Printf("INFO: to ignore leaks on libFuzzer side use -detect_leaks=0.\n\n");
    CurrentUnitSize = Size;
    DumpCurrentUnit("leak-");
    PrintFinalStats();
    _Exit(Options.ErrorExitCode); // not exit() to disable lsan further on.
  }
}

void Fuzzer::MutateAndTestOne() {
  MD.StartMutationSequence();

  auto &II = Corpus.ChooseUnitToMutate(MD.GetRand());
  if (Options.DoCrossOver) {
    auto &CrossOverII = Corpus.ChooseUnitToCrossOverWith(
        MD.GetRand(), Options.CrossOverUniformDist);
    MD.SetCrossOverWith(&CrossOverII.U);
  }
  const auto &U = II.U;
  memcpy(BaseSha1, II.Sha1, sizeof(BaseSha1));
  assert(CurrentUnitData);
  size_t Size = U.size();
  assert(Size <= MaxInputLen && "Oversized Unit");
  memcpy(CurrentUnitData, U.data(), Size);

  assert(MaxMutationLen > 0);

  size_t CurrentMaxMutationLen =
      Min(MaxMutationLen, Max(U.size(), TmpMaxMutationLen));
  assert(CurrentMaxMutationLen > 0);

  for (int i = 0; i < Options.MutateDepth; i++) {
    if (TotalNumberOfRuns >= Options.MaxNumberOfRuns)
      break;
    MaybeExitGracefully();
    size_t NewSize = 0;
    if (II.HasFocusFunction && !II.DataFlowTraceForFocusFunction.empty() &&
        Size <= CurrentMaxMutationLen)
      NewSize = MD.MutateWithMask(CurrentUnitData, Size, Size,
                                  II.DataFlowTraceForFocusFunction);

    // If MutateWithMask either failed or wasn't called, call default Mutate.
    if (!NewSize)
      NewSize = MD.Mutate(CurrentUnitData, Size, CurrentMaxMutationLen);
    assert(NewSize > 0 && "Mutator returned empty unit");
    assert(NewSize <= CurrentMaxMutationLen && "Mutator return oversized unit");
    Size = NewSize;
    II.NumExecutedMutations++;
    Corpus.IncrementNumExecutedMutations();

    bool FoundUniqFeatures = false;
    bool NewCov = RunOne(CurrentUnitData, Size, /*MayDeleteFile=*/true, &II,
                         /*ForceAddToCorpus*/ false, &FoundUniqFeatures);
    TryDetectingAMemoryLeak(CurrentUnitData, Size,
                            /*DuringInitialCorpusExecution*/ false);
    if (NewCov) {
      ReportNewCoverage(&II, {CurrentUnitData, CurrentUnitData + Size});
      break;  // We will mutate this input more in the next rounds.
    }
    if (Options.ReduceDepth && !FoundUniqFeatures)
      break;
  }

  II.NeedsEnergyUpdate = true;
}

// choose a corpus M=M1+M2. M1 not change, only mutate M2
void Fuzzer::MutateAndTestOne_FSM() { 
  MD.StartMutationSequence();

  // auto &II = Corpus.ChooseUnitToMutate(MD.GetRand());   // randomly choose one to mutate
  auto &II = state_corpus[cur_state.id].ChooseUnitToMutate(MD.GetRand());
  // if (Options.DoCrossOver) {
  //   auto &CrossOverII = Corpus.ChooseUnitToCrossOverWith(
  //       MD.GetRand(), Options.CrossOverUniformDist);
  //   MD.SetCrossOverWith(&CrossOverII.U);
  // }
  if (Options.DoCrossOver) {
    auto &CrossOverII = state_corpus[cur_state.id].ChooseUnitToCrossOverWith(
        MD.GetRand(), Options.CrossOverUniformDist);
    MD.SetCrossOverWith(&CrossOverII.U);
  }

  const auto &U = II.U;       // get fuzz input
  memcpy(BaseSha1, II.Sha1, sizeof(BaseSha1));
  assert(CurrentUnitData);

  // Printf("798 U size=%d\n",U.size());
  // for (int i=0; i<U.size(); i++)
  //   Printf("%d",U[i]);
  // Printf("\n");

  int sep_pos=find_sep_pos(U);    // split input to m1 and m2. 
  // Printf("sep_pos=%d\n",sep_pos);

  size_t Size = U.size();
  assert(Size <= MaxInputLen && "Oversized Unit");
  memcpy(CurrentUnitData, U.data(), Size);

  assert(MaxMutationLen > 0);

  // size_t CurrentMaxMutationLen =
  //     Min(MaxMutationLen, Max(U.size(), TmpMaxMutationLen)); 
  size_t CurrentMaxMutationLen =
      Min(MaxMutationLen, Max(U.size()-sep_pos, TmpMaxMutationLen));    // U.size()-sep_pos ?
  assert(CurrentMaxMutationLen > 0);

  for (int i = 0; i < Options.MutateDepth; i++) {
    if (TotalNumberOfRuns >= Options.MaxNumberOfRuns)
      break;
    MaybeExitGracefully();
    size_t NewSize = 0;

    // only mutate bytes after sep_pos(m2)
    if (II.HasFocusFunction && !II.DataFlowTraceForFocusFunction.empty() &&
        Size <= CurrentMaxMutationLen)
      NewSize = MD.MutateWithMask(CurrentUnitData+sep_pos, Size-sep_pos, Size-sep_pos,
                                  II.DataFlowTraceForFocusFunction);

    // If MutateWithMask either failed or wasn't called, call default Mutate.
    if (!NewSize) {
      NewSize = MD.Mutate(CurrentUnitData+sep_pos, Size-sep_pos, CurrentMaxMutationLen);
      // NewSize = MD.Mutate(CurrentUnitData, Size, CurrentMaxMutationLen);
      // Printf("mutate here 831, NewSize=%zu\n", NewSize);
      // note: 'CurrentUnitData' is changed in Mutate/MutateWithMask
    }

    assert(NewSize > 0 && "Mutator returned empty unit");
    assert(NewSize <= CurrentMaxMutationLen && "Mutator return oversized unit");
    // Size = NewSize;
    Size = NewSize+sep_pos;   // add sep_pos
    II.NumExecutedMutations++;
    Corpus.IncrementNumExecutedMutations();
    state_corpus[cur_state.id].IncrementNumExecutedMutations();
    bool FoundUniqFeatures = false;

    bool NewCov = RunOne(CurrentUnitData, Size, /*MayDeleteFile=*/true, &II,
                         /*ForceAddToCorpus*/ false, &FoundUniqFeatures);   
    // note: run the mutated input. will add to corpus by Corpus.AddToCorpus

    TryDetectingAMemoryLeak(CurrentUnitData, Size,
                            /*DuringInitialCorpusExecution*/ false);

    if (NewCov) {
      ReportNewCoverage(&II, {CurrentUnitData, CurrentUnitData + Size});  
      // note: will save 'CurrentUnitData' by WriteToOutputCorpus(U) in ReportNewCoverage()
      break;  // We will mutate this input more in the next rounds.
    }

    if (Options.ReduceDepth && !FoundUniqFeatures)
      break;
  }

  II.NeedsEnergyUpdate = true;
}

void Fuzzer::reverse_data(uint8_t* data, size_t size) {
  uint8_t tmp;
  for (size_t i=0; i<size; i++) {
    tmp=data[i];
    data[i]=data[size-i-1];
    data[size-i-1]=tmp;
  }
}

int Fuzzer::find_sep_pos(const Unit &U) {
  int cur=fixed_consume_size;
  while (true) {
    if (U[cur]==m1_m2_sep) break;
    cur+=(U[cur]+1);     // go through a packet in m1
  }
  return cur+1;
}

State Fuzzer::choose_state() {
  for (int i=0; i<fsm.states.size(); i++) {
    State state=fsm.states[i];
    if (state_executed[state.id]==0)
      return state;
  }
  return State(-1);
}

// TBD: parse KLEE transitions
void Fuzzer::initialize_FSM() {

  for (int i=0; i<max_state_num; i++) {
    state_exec_times[i]=0;
    state_executed[i]=false;
  }
  // fake, for test now
  fsm=FSM();
  State state_1(1);
  fsm.states.push_back(state_1);
  State state_2(2);
  fsm.states.push_back(state_2);

}

// std::vector<uint8_t> Fuzzer::get_access_sequence (State s)
// TBD:  (1) use state s, (2) pre-process io_req, (3) parse from FSM
std::vector<uint8_t> Fuzzer::get_access_sequence (State s) {

  /* auto is_br = fdp.ConsumeBool();         1 byte
  auto is_initiator = fdp.ConsumeBool();     1 byte
  is_peripheral = fdp.ConsumeBool();         1 byte
  fdp.ConsumeData(&io_req, sizeof(io_req));  6 byte
  */

  std::vector<uint8_t> result;

  // for test
  if (s.id==1) { // 010 + ...
    result={0,1,0, 0,0,0,0,0,0};
  }

  if (s.id==2) {
    result={0,1,1, 0,0,0,0,0,0};
  }

  // TBD: add packet
  result.push_back(m1_m2_sep);

  return result;
}

void Fuzzer::PurgeAllocator() {
  if (Options.PurgeAllocatorIntervalSec < 0 || !EF->__sanitizer_purge_allocator)
    return;
  if (duration_cast<seconds>(system_clock::now() -
                             LastAllocatorPurgeAttemptTime)
          .count() < Options.PurgeAllocatorIntervalSec)
    return;

  if (Options.RssLimitMb <= 0 ||
      GetPeakRSSMb() > static_cast<size_t>(Options.RssLimitMb) / 2)
    EF->__sanitizer_purge_allocator();

  LastAllocatorPurgeAttemptTime = system_clock::now();
}

void Fuzzer::ReadAndExecuteSeedCorpora(Vector<SizedFile> &CorporaFiles) {
  const size_t kMaxSaneLen = 1 << 20;
  const size_t kMinDefaultLen = 4096;
  size_t MaxSize = 0;
  size_t MinSize = -1;
  size_t TotalSize = 0;
  for (auto &File : CorporaFiles) {
    MaxSize = Max(File.Size, MaxSize);
    MinSize = Min(File.Size, MinSize);
    TotalSize += File.Size;
  }
  if (Options.MaxLen == 0)
    SetMaxInputLen(std::min(std::max(kMinDefaultLen, MaxSize), kMaxSaneLen));
  assert(MaxInputLen > 0);

  // Test the callback with empty input and never try it again.
  uint8_t dummy = 0;
  ExecuteCallback(&dummy, 0);

  if (CorporaFiles.empty()) {
    Printf("INFO: A corpus is not provided, starting from an empty corpus\n");
    Unit U({'\n'}); // Valid ASCII input.
    RunOne(U.data(), U.size());     //*
  } else {
    Printf("INFO: seed corpus: files: %zd min: %zdb max: %zdb total: %zdb"
           " rss: %zdMb\n",
           CorporaFiles.size(), MinSize, MaxSize, TotalSize, GetPeakRSSMb());
    if (Options.ShuffleAtStartUp)
      std::shuffle(CorporaFiles.begin(), CorporaFiles.end(), MD.GetRand());

    if (Options.PreferSmall) {
      std::stable_sort(CorporaFiles.begin(), CorporaFiles.end());
      assert(CorporaFiles.front().Size <= CorporaFiles.back().Size);
    }

    // Load and execute inputs one by one.
    for (auto &SF : CorporaFiles) {
      auto U = FileToVector(SF.File, MaxInputLen, /*ExitOnError=*/false);
      assert(U.size() <= MaxInputLen);
      RunOne(U.data(), U.size(), /*MayDeleteFile*/ false, /*II*/ nullptr,
             /*ForceAddToCorpus*/ Options.KeepSeed,
             /*FoundUniqFeatures*/ nullptr);           //*
      CheckExitOnSrcPosOrItem();
      TryDetectingAMemoryLeak(U.data(), U.size(),
                              /*DuringInitialCorpusExecution*/ true);
    }
  }

  PrintStats("INITED");
  if (!Options.FocusFunction.empty()) {
    Printf("INFO: %zd/%zd inputs touch the focus function\n",
           Corpus.NumInputsThatTouchFocusFunction(), Corpus.size());
    if (!Options.DataFlowTrace.empty())
      Printf("INFO: %zd/%zd inputs have the Data Flow Trace\n",
             Corpus.NumInputsWithDataFlowTrace(),
             Corpus.NumInputsThatTouchFocusFunction());
  }

  if (Corpus.empty() && Options.MaxNumberOfRuns) {
    Printf("ERROR: no interesting inputs were found. "
           "Is the code instrumented for coverage? Exiting.\n");
    exit(1);
  }
}

void Fuzzer::ReadAndExecuteSeedCorpora_FSM(Vector<SizedFile> &CorporaFiles) {
  const size_t kMaxSaneLen = 1 << 20;
  const size_t kMinDefaultLen = 4096;
  size_t MaxSize = 0;
  size_t MinSize = -1;
  size_t TotalSize = 0;
  for (auto &File : CorporaFiles) {
    MaxSize = Max(File.Size, MaxSize);
    MinSize = Min(File.Size, MinSize);
    TotalSize += File.Size;
  }
  if (Options.MaxLen == 0)
    SetMaxInputLen(std::min(std::max(kMinDefaultLen, MaxSize), kMaxSaneLen));
  assert(MaxInputLen > 0);

  // Test the callback with empty input and never try it again. 
  // note: temporary comment out to avoid Fuzz_FSM() SEGV
  // uint8_t dummy = 0;
  // ExecuteCallback(&dummy, 0);

  if (CorporaFiles.empty()) {
    Printf("INFO: A corpus is not provided, starting from a state\n");
    // Unit U({'\n'}); // Valid ASCII input.  
    // note: get one state and access sequence, as initial corpus
    Unit U;
    State initial_s=choose_state();
    cur_state.id=initial_s.id;
    std::vector<uint8_t> initial_m1=get_access_sequence(initial_s);
    for (int i=0; i<initial_m1.size(); i++)
      U.push_back(initial_m1[i]);
    U.push_back(1);
    RunOne(U.data(), U.size());     // run initial corpus
  } else {
    Printf("INFO: seed corpus: files: %zd min: %zdb max: %zdb total: %zdb"
           " rss: %zdMb\n",
           CorporaFiles.size(), MinSize, MaxSize, TotalSize, GetPeakRSSMb());
    if (Options.ShuffleAtStartUp)
      std::shuffle(CorporaFiles.begin(), CorporaFiles.end(), MD.GetRand());

    if (Options.PreferSmall) {
      std::stable_sort(CorporaFiles.begin(), CorporaFiles.end());
      assert(CorporaFiles.front().Size <= CorporaFiles.back().Size);
    }

    // Load and execute inputs one by one.
    for (auto &SF : CorporaFiles) {
      auto U = FileToVector(SF.File, MaxInputLen, /*ExitOnError=*/false);
      assert(U.size() <= MaxInputLen);
      RunOne(U.data(), U.size(), /*MayDeleteFile*/ false, /*II*/ nullptr,
             /*ForceAddToCorpus*/ Options.KeepSeed,
             /*FoundUniqFeatures*/ nullptr);           // run seed
      CheckExitOnSrcPosOrItem();
      TryDetectingAMemoryLeak(U.data(), U.size(),
                              /*DuringInitialCorpusExecution*/ true);
    }
  }

  PrintStats("INITED");
  if (!Options.FocusFunction.empty()) {
    Printf("INFO: %zd/%zd inputs touch the focus function\n",
           Corpus.NumInputsThatTouchFocusFunction(), Corpus.size());
    if (!Options.DataFlowTrace.empty())
      Printf("INFO: %zd/%zd inputs have the Data Flow Trace\n",
             Corpus.NumInputsWithDataFlowTrace(),
             Corpus.NumInputsThatTouchFocusFunction());
  }

  if (Corpus.empty() && Options.MaxNumberOfRuns) {
    Printf("ERROR: no interesting inputs were found. "
           "Is the code instrumented for coverage? Exiting.\n");
    exit(1);
  }
}

void Fuzzer::Loop(Vector<SizedFile> &CorporaFiles) {
  auto FocusFunctionOrAuto = Options.FocusFunction;
  DFT.Init(Options.DataFlowTrace, &FocusFunctionOrAuto, CorporaFiles,
           MD.GetRand());
  TPC.SetFocusFunction(FocusFunctionOrAuto);

  ReadAndExecuteSeedCorpora(CorporaFiles);             // note: read and execute seed. has RunOne(0)
  
  DFT.Clear();  // No need for DFT any more.
  TPC.SetPrintNewPCs(Options.PrintNewCovPcs);
  TPC.SetPrintNewFuncs(Options.PrintNewCovFuncs);
  system_clock::time_point LastCorpusReload = system_clock::now();

  TmpMaxMutationLen =
      Min(MaxMutationLen, Max(size_t(4), Corpus.MaxInputSize()));

  while (true) {

    auto Now = system_clock::now();
    if (!Options.StopFile.empty() &&
        !FileToVector(Options.StopFile, 1, false).empty())
      break;
    if (duration_cast<seconds>(Now - LastCorpusReload).count() >=
        Options.ReloadIntervalSec) {
      RereadOutputCorpus(MaxInputLen);                  // note: reread and reload, has RunOne()
      LastCorpusReload = system_clock::now();
    }
    if (TotalNumberOfRuns >= Options.MaxNumberOfRuns)
      break;
    if (TimedOut())
      break;

    // Update TmpMaxMutationLen
    if (Options.LenControl) {
      if (TmpMaxMutationLen < MaxMutationLen &&
          TotalNumberOfRuns - LastCorpusUpdateRun >
              Options.LenControl * Log(TmpMaxMutationLen)) {
        TmpMaxMutationLen =
            Min(MaxMutationLen, TmpMaxMutationLen + Log(TmpMaxMutationLen));
        LastCorpusUpdateRun = TotalNumberOfRuns;
      }
    } else {
      TmpMaxMutationLen = MaxMutationLen;
    }

    // Perform several mutations and runs.
    MutateAndTestOne();                    // mutate and testone. has RunOne()

    PurgeAllocator();

  }

  PrintStats("DONE  ", "\n");
  MD.PrintRecommendedDictionary();
}

void Fuzzer::Loop_FSM(Vector<SizedFile> &CorporaFiles) {
  // Printf("ENTER LOOP_FSM 1123\n");
  auto FocusFunctionOrAuto = Options.FocusFunction;
  DFT.Init(Options.DataFlowTrace, &FocusFunctionOrAuto, CorporaFiles,
           MD.GetRand());
  TPC.SetFocusFunction(FocusFunctionOrAuto);

  ReadAndExecuteSeedCorpora_FSM(CorporaFiles);   // note: read and execute seed. has RunOne()

  DFT.Clear();  // No need for DFT any more.
  TPC.SetPrintNewPCs(Options.PrintNewCovPcs);
  TPC.SetPrintNewFuncs(Options.PrintNewCovFuncs);
  system_clock::time_point LastCorpusReload = system_clock::now();

  TmpMaxMutationLen =
      Min(MaxMutationLen, Max(size_t(4), Corpus.MaxInputSize()));

  while (true) {

    // compare (1) cur_cov and last_cov, (2) execute times with max_state_exec,  to decide state change
    cur_cov=TPC.GetTotalPCCoverage();
    if (state_exec_times[cur_state.id]>=max_state_exec || cur_cov==last_cov) {
      auto Now=system_clock::now();
      if (state_exec_times[cur_state.id]>=max_state_exec ||
      duration_cast<seconds>(Now - last_cov_upd).count() >= state_cov_interval) {
        Printf("choose a new state...\n");
        state_executed[cur_state.id]=true;
        cur_state=choose_state();
        std::vector<uint8_t> m1=get_access_sequence(cur_state);  // TBD: where to generate and use m1 ?
        Unit U;
        for (int i=0; i<m1.size(); i++)
          U.push_back(m1[i]);
        U.push_back(1);
        RunOne(U.data(), U.size());     // run one test for new state
      }
    } else {
      last_cov=cur_cov;
      last_cov_upd=system_clock::now();
    }
    // Printf("cur_state id=%d, exec times=%d\n", cur_state.id, state_exec_times[cur_state.id]);

    auto Now = system_clock::now();
    if (!Options.StopFile.empty() &&
        !FileToVector(Options.StopFile, 1, false).empty())
      break;
    if (duration_cast<seconds>(Now - LastCorpusReload).count() >=
        Options.ReloadIntervalSec) {
      RereadOutputCorpus(MaxInputLen);                  // note: reread and reload, has RunOne()
      LastCorpusReload = system_clock::now();
    }

    if (TotalNumberOfRuns >= Options.MaxNumberOfRuns)
      break;
    if (TimedOut())
      break;

    // Update TmpMaxMutationLen
    if (Options.LenControl) {
      if (TmpMaxMutationLen < MaxMutationLen &&
          TotalNumberOfRuns - LastCorpusUpdateRun >
              Options.LenControl * Log(TmpMaxMutationLen)) {
        TmpMaxMutationLen =
            Min(MaxMutationLen, TmpMaxMutationLen + Log(TmpMaxMutationLen));
        LastCorpusUpdateRun = TotalNumberOfRuns;
      }
    } else {
      TmpMaxMutationLen = MaxMutationLen;
    }

    // Perform several mutations and runs.
    MutateAndTestOne_FSM();                    // mutate and testone. has RunOne()

    PurgeAllocator();
  }

  PrintStats("DONE  ", "\n");
  MD.PrintRecommendedDictionary();
}

void Fuzzer::MinimizeCrashLoop(const Unit &U) {
  if (U.size() <= 1)
    return;
  while (!TimedOut() && TotalNumberOfRuns < Options.MaxNumberOfRuns) {
    MD.StartMutationSequence();
    memcpy(CurrentUnitData, U.data(), U.size());
    for (int i = 0; i < Options.MutateDepth; i++) {
      size_t NewSize = MD.Mutate(CurrentUnitData, U.size(), MaxMutationLen);
      assert(NewSize > 0 && NewSize <= MaxMutationLen);
      ExecuteCallback(CurrentUnitData, NewSize);
      PrintPulseAndReportSlowInput(CurrentUnitData, NewSize);
      TryDetectingAMemoryLeak(CurrentUnitData, NewSize,
                              /*DuringInitialCorpusExecution*/ false);
    }
  }
}

} // namespace fuzzer

extern "C" {

ATTRIBUTE_INTERFACE size_t
LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
  assert(fuzzer::F);
  return fuzzer::F->GetMD().DefaultMutate(Data, Size, MaxSize);
}

} // extern "C"
