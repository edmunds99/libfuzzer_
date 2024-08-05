
#include <iostream>
#include <vector>
#include <map>
#include <cstdint>

class State {
public:
    std::vector<int> state;   // more than 1 state variable (sv)
    int id;

    State(std::initializer_list<int> init) : state(init) {}

    bool operator<(const State& other) const {
        return state < other.state;
    }
};

using Packet = std::vector<uint8_t>;

// define a comparator
struct StatePairComp {
    bool operator()(const std::pair<State, State>& a, const std::pair<State, State>& b) const {
        if (a.first < b.first) return true;
        if (b.first < a.first) return false;
        return a.second < b.second;
    }
};

class FSM {
private:
    std::map<std::pair<State, State>, Packet, StatePairComp> transitions;

public:
    
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
            for (auto i : transition.first.first.state) std::cout << i << " ";
            std::cout << "] to state [";
            for (auto i : transition.first.second.state) std::cout << i << " ";
            std::cout << "] with packet: ";
            for (auto byte : transition.second) std::cout << std::hex << static_cast<int>(byte) << " ";
            std::cout << std::endl;
        }
    }
};

// TBD: add more test to this FSM

// int main() {
//     FSM fsm;
//     State s1 = {1, 2, 3};
//     State s2 = {4, 5, 6};
//     Packet packet = {0x01, 0x02, 0x03};

//     fsm.addTransition(s1, s2, packet);
//     fsm.printTransitions();

//     Packet foundPacket = fsm.getTransitionPacket(s1, s2);
//     if (!foundPacket.empty()) {
//         std::cout << "Found packet for transition: ";
//         for (auto byte : foundPacket) std::cout << std::hex << static_cast<int>(byte) << " ";
//         std::cout << std::endl;
//     } else {
//         std::cout << "No transition found." << std::endl;
//     }

//     return 0;
// }