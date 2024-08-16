
#include <iostream>
#include <vector>
#include <map>
#include <cstdint>

class State {
public:
	std::vector<int> state;   // more than 1 state variable (sv)
	int id;

	State() {} 
	State(int id) : id(id) {} 
	State(const std::vector<int>& init) : state(init) {}  
	State(const std::vector<int>& init, int id = 0) : state(init), id(id) {} 

	bool operator<(const State& other) const {
		return state < other.state;
	}
};

using Packet = std::vector<uint8_t>;
using PacketList = std::vector<Packet>;

// define a comparator
struct StatePairComp {
	bool operator()(const std::pair<State, State>& a, const std::pair<State, State>& b) const {
		if (a.first < b.first) return true;
		if (b.first < a.first) return false;
		return a.second < b.second;
	}
};

class FSM {

public:

	std::vector<State> states;
	std::map<std::pair<State, State>, Packet, StatePairComp> transitions;
	std::map<State, PacketList> stateToPacketsMap;

	// some fake values, for manual create M1
	std::vector<uint8_t> fake_confirm;
	std::vector<uint8_t> fake_rand;
	std::vector<uint8_t> fake_pub_key;
	std::vector<uint8_t> fake_dhkey_check;
	uint32_t fixed_eccx[8] = {
   		2198633781, 2475574431, 2735915610, 1722828383, 3606873419, 2458771352, 2385206393, 1720691774,
	};
	const uint32_t fixed_eccy[8] = {
   		2556214130, 2565982928, 3359245577, 1000677376, 3540911383, 3871339133, 422803352, 122696205,
	};
	uint8_t fixed_ecc32x[32]={0};
	uint8_t fixed_ecc32y[32]={0};

	void addTransition(const State& from, const State& to, const Packet& packet) {
		transitions[std::make_pair(from, to)] = packet;
	}

	Packet getTransitionPacket(const State& from, const State& to) const {
		auto key = std::make_pair(from, to);
		auto it = transitions.find(key);
		if (it != transitions.end()) {
			return it->second;
		}
		return {};
	}

	void printTransitions() const {
		for (const auto& transition : transitions) {
			std::cout << "Transition from state [";
			for (auto i : transition.first.first.state) std::cout << i << ' ';
			std::cout << "] to state [";
			for (auto i : transition.first.second.state) std::cout << i << ' ';
			std::cout << "] with packet: ";
			for (auto byte : transition.second) std::cout << std::hex << static_cast<int>(byte) << " ";
			std::cout << std::endl;
		}
	}

	void initialize_fake_value() {
		fake_confirm.resize(17,0); fake_confirm[0]=3;
		fake_rand.resize(17,0); fake_rand[0]=4;

		fake_pub_key.resize(65,0); fake_pub_key[0]=12;
		memcpy(fixed_ecc32x, fixed_eccx, 32);
      	memcpy(fixed_ecc32y, fixed_eccy, 32);
		for (int i=1; i<=32; i++) fake_pub_key[i]=fixed_ecc32x[i-1];
      	for (int i=33; i<=64; i++) fake_pub_key[i]=fixed_ecc32y[i-33];
		
		fake_dhkey_check.resize(17,0); fake_dhkey_check[0]=13;
	}

	void CreateManualAccessSeq() {

	}
};

/* add test to this FSM */

// int main() {

// 	// test FSM transitions
// 	FSM fsm;
// 	State s1 = { 1, 2, 3 };
// 	State s2 = { 4, 5, 6 };
// 	State s3 = { 7, 8, 9 };
// 	State s4 = { 13, 14, 15 };
// 	Packet packet = { 0x01, 0x02, 0x03 };
// 	Packet packet2 = { 0x04, 0x05, 0x06, 0X07, 0X08 };

// 	fsm.addTransition(s1, s2, packet);
// 	fsm.printTransitions();

// 	Packet foundPacket = fsm.getTransitionPacket(s1, s2);
// 	if (!foundPacket.empty()) {
// 		std::cout << "Found packet for transition: ";
// 		for (auto byte : foundPacket) std::cout << std::hex << static_cast<int>(byte) << " ";
// 		std::cout << std::endl;
// 	}
// 	else {
// 		std::cout << "No transition found." << std::endl;
// 	}

// 	Packet noTransitionPacket = fsm.getTransitionPacket(s2, s3);
// 	if (noTransitionPacket.empty()) {
// 		std::cout << "Correctly identified no transition." << std::endl;
// 	}
// 	else {
// 		std::cout << "Error: Transition should not exist." << std::endl;
// 	}

// 	fsm.addTransition(s1, s4, packet2);
// 	fsm.printTransitions(); 

// 	// test access sequence to a state 
//     State s1({1, 2, 3});
//     PacketList packets = {
//         {0x01, 0x02, 0x03},
//         {0x04, 0x05, 0x06}
//     };

//     fsm.stateToPacketsMap[s1] = packets;
//     for (const auto& pair : fsm.stateToPacketsMap) {
//         std::cout << "State ID: " << pair.first.id << std::endl;
//         for (const auto& packet : pair.second) {
//             std::cout << "Packet: ";
//             for (uint8_t byte : packet) {
//                 std::cout << std::hex << static_cast<int>(byte) << " ";
//             }
//             std::cout << std::endl;
//         }
//     }

// 	return 0;
// }