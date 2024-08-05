#include <algorithm>
#include <vector>
#include <cstring>
#include <string>
#include <cstdlib>

namespace fuzzer {
    const int MaxState=20;
    const int MaxEvt=50;
    const int MaxPathCond=100;
    const std::string fsmDir="/scratch/wjw5351/aosp/packages/modules/Bluetooth/system/stack/analyzers/result/extract_sym_example.txt";

    // symname, symvalue;
    struct sym {
        std::string name;
        std::string hex;
        uint8_t value;
    };

    class FSM {
        public:
            std::vector<std::vector<sym>> trans[MaxState][MaxState][MaxEvt];

            FSM();
            ~FSM();

            int checkTrans(int s1, int s2);
            bool printCond(int s1, int s2, int e);
            bool readFSMfile(const std::string& filename);

            std::vector<int> parseNum(const std::string& line);
            sym parseObj(const std::string& line);
    
    };

}