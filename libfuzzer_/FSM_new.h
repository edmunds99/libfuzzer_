#include <iostream>
#include <vector>
#include <map>
#include <cstdint>
#include <fstream>
#include <iomanip> // For std::hex and std::setw

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
	std::map<State, PacketList> StateToPackets;
	std::map<int, std::vector<uint8_t>> AccSeq;   // key is state id

	// some fake values, for manual create M1
	uint32_t fixed_eccx[8] = {2198633781, 2475574431, 2735915610, 1722828383, 3606873419, 2458771352, 2385206393, 1720691774};
	uint32_t fixed_eccy[8] = {2556214130, 2565982928, 3359245577, 1000677376, 3540911383, 3871339133, 422803352, 122696205};
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

	void parseAccSeq(const std::string& filepath) {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << filepath << std::endl;
            return;
        }

        std::string line;
        int stateId;
        std::vector<int> stateVars;
        std::vector<uint8_t> packetData;

        while (getline(file, line)) {
            if (line.empty()) continue;   // Skip empty lines

            std::istringstream iss(line);
            iss >> stateId;  // Read state ID from the first line

            // Read the second line as state variables
            if (getline(file, line)) {
                iss.str(line);
                iss.clear();
                stateVars.clear();

                int var;
                while (iss >> var) {
                    stateVars.push_back(var);
                }

                states.push_back(State(stateVars, stateId));  // Store the state
            }

            // Read the third line as packet data
            if (getline(file, line)) {
                iss.str(line);
                iss.clear();
                packetData.clear();

                int byte;
				if (stateVars[1]==3) packetData.push_back(1);  // flag for initial state
				else packetData.push_back(2);  // flag for regular state
                while (iss >> byte) {
                    packetData.push_back(static_cast<uint8_t>(byte));
                }

                AccSeq[stateId] = packetData;  // Update the map with the new state and its packet data
            }
        }

        file.close();
    }

	void printAccSeq() {
		for (size_t i=0; i<states.size(); i++) {
			std::cout << "state id:" << states[i].id<<std::endl;
			std::cout << "state"<<' ';
			for (size_t j=0; j<states[i].state.size(); j++)
				std::cout << states[i].state[j] << ' ';
			std::cout << std::endl;
			std::cout << "acc seq:"<<std::endl;
			for (size_t j=0; j<AccSeq[states[i].id].size(); j++)
				std::cout <<static_cast<int>(AccSeq[states[i].id][j]) <<' ';
			std::cout<<std::endl;
			std::cout<<std::endl;
		}
    }

	void parseFSM(std::string filepath) {

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

//     fsm.accSeq[s1] = packets;
//     for (const auto& pair : fsm.accSeq) {
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