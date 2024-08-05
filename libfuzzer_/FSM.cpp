#include <algorithm>
#include <vector>
#include <cstring>
#include <string>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>

#include "FSM.h"
#include "FuzzerIO.h"

// FSM for single state variable
namespace fuzzer {

    FSM::FSM() {
        for (int s1=0; s1<MaxState; s1++)
            for (int s2=0; s2<MaxState; s2++)
                for (int e=0; e<MaxEvt; e++)
                    trans[s1][s2][e].clear();
    }
    FSM::~FSM(){}

    int FSM::checkTrans(int s1, int s2) {
        for (int e=0; e<MaxEvt; e++)
            if (trans[s1][s2][e].size()>0)
                return e;
        return -1;
    }

    bool FSM::printCond(int s1, int s2, int e) {
        for (int i=0; i<trans[s1][s2][e].size(); i++) {
            Printf("Condition %d of state %d transfer to state %d with event %d\n:",i,s1,s2,e);
            for (int j=0; j<trans[s1][s2][e][i].size(); j++) {
                Printf("symname=%s, symhex=%d\n",trans[s1][s2][e][i][j].name.c_str(), trans[s1][s2][e][i][j].hex.c_str());
            }
        }
        return true;
    }

    bool FSM::readFSMfile(const std::string& filename) {

        Printf("enter readFSMfile\n");

        std::ifstream infile(filename);
        std::string line;

        while (std::getline(infile, line)) {
            std::vector<int> tran = parseNum(line);
            int s1=tran[0], s2=tran[1], e=tran[2];
            //printf("s1=%d, s2=%d, e=%d\n",s1, s2, e);

            if (s1<0 || s1>MaxState || s2<0 || s2>MaxState || e<0 || e>MaxEvt)
                return false;

            std::getline(infile, line);
            int numObj = std::stoi(line);
            //printf("numObj=%d\n",numObj);

            std::vector<sym> syms;
            trans[s1][s2][e].push_back(syms);
            int sz=trans[s1][s2][e].size();
            for (int i = 0; i < numObj; i++) {
                std::getline(infile, line);
                trans[s1][s2][e][sz-1].push_back(parseObj(line));
            }

            std::getline(infile, line);
        }
        return true;
    }

    std::vector<int> FSM::parseNum(const std::string& line) {
        std::vector<int> numbers;
        std::stringstream ss(line);
        std::string item;
        while (std::getline(ss, item, ',')) {
            numbers.push_back(std::stoi(item));
        }
        return numbers;
    }

    sym FSM::parseObj(const std::string& line) {
        std::stringstream ss(line);
        std::string name, hex_value;
        std::getline(ss, name, ',');
        std::getline(ss, hex_value, ',');
        return {name, hex_value};
    }
}   