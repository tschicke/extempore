#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <utility>
#include <array>
#include <iomanip>
#include <functional>

#ifndef USE_MATH         /* If math support is needed */
# define USE_MATH 1
#endif

#ifndef USE_CHAR_CLASSIFIERS  /* If char classifiers are needed */
# define USE_CHAR_CLASSIFIERS 1
#endif

#ifndef USE_ASCII_NAMES  /* If extended escaped characters are needed */
# define USE_ASCII_NAMES 1
#endif

#ifndef USE_STRING_PORTS      /* Enable string ports */
# define USE_STRING_PORTS 1
#endif

#ifndef USE_TRACING
# define USE_TRACING 1
#endif

const char *opcode_names[] = {
#define _OP_DEF(A,B,C,D,E,OP) #OP,
#include "OPDefines.h"
	"RET",
};

typedef uint8_t opcode;

/* operator code */
enum scheme_opcodes {
#define _OP_DEF(A,B,C,D,E,OP) OP,
#include "OPDefines.h"
	OP_RET,
    OP_MAXDEFINED
};

class Reader {
public:
	enum ExecState {
		STATE_BREAKPOINT,
		STATE_STOP,
		STATE_FINISH
	};
	struct ip_stack {
		ip_stack(Reader *reader, uint64_t ip)
			: m_reader(reader), m_ip(reader->push(ip)) {
		}
		~ip_stack() {
			m_reader->pop(m_ip);
		}
	private:
		Reader *m_reader;
		uint64_t m_ip;
	};

	ip_stack get_ip_frame(uint64_t ip) {
		return ip_stack(this, ip);
	}

	Reader() :
		m_ip(0),
		m_hitcounts{} {
	}

	bool load(std::string filename) {
		std::ifstream file(filename, std::ios::binary | std::ios::ate);
		if(!file.is_open()) {
			std::cerr << "Can't open file out.log" << std::endl;
			return false;
		}
		std::streamsize size = file.tellg();
		file.seekg(0);

		m_buffer.resize(size);
		m_breakpoints.resize(size);
		if(!file.read((char *)m_buffer.data(), size)) {
			std::cerr << "Can't read file into buffer" << std::endl;
			return false;
		}
		file.close();
		return true;
	}

	opcode getCurrentOp() {
		return getOp(getIp());
	}

	opcode getOp(uint64_t ip) {
		opcode op = m_buffer[ip];
		return op == 254 ? OP_RET : op;
	}

	uint64_t getNumOps() {
		return m_buffer.size();
	}

	uint64_t getIp() {
		return m_ip;
	}

	void print(std::string fmt) {
		size_t i = 0, size = fmt.size();
		while(i < size) {
			char c = fmt[i];

			if (c == '%') {
				if(i < size - 1) {
					switch(fmt[i + 1]) {
					case 'i':
						std::cout << m_ip;
						break;
					case 'o': {
						opcode op = getCurrentOp();
						if(isValidOp(op)) {
							std::cout << opcode_names[op];
						} else {
							std::cout << "!ERR!";
						}
						break;
					}
					case '%':
						std::cout << "%";
						break;
					default:
						break;
					}
					i += 2;
				} else {
					i++;
				}
			} else if (c == '\\') {
				if(i < size - 1) {
					switch(fmt[i + 1]) {
					case 'n':
						std::cout << '\n';
						break;
					case 't':
						std::cout << '\t';
						break;
					case '\\':
						std::cout << '\\';
						break;
					default:
						break;
					}
					i += 2;
				} else {
					i++;
				}
			} else {
				std::cout << c;
				i++;
			}
		}
	}

	bool atBreakpoint() {
		return m_breakpoints[getIp()];
	}

	ExecState step() {
		m_ip += getCurrentInstructionSize();
		if(m_ip >= m_buffer.size()) {
			return STATE_FINISH;
		}
		m_hitcounts[getCurrentOp()]++;
		if(atBreakpoint()) {
			return STATE_BREAKPOINT;
		}
		return STATE_STOP;
	}

	ExecState finish() {
		while(getCurrentOp() != OP_RET) {
			ExecState status = step();
			if(status != STATE_STOP) {
				return status;
			}
		}
		return STATE_STOP;
	}

	ExecState cont() {
		while(true) {
			ExecState status = step();
			if(status != STATE_STOP) {
				return status;
			}
		}
	}

	void jump(uint64_t ip) {
		m_ip = ip;
	}

	uint64_t push(uint64_t ip) {
		uint64_t currentIp = getIp();
		jump(ip);
		return currentIp;
	}

	void pop(uint64_t ip) {
		jump(ip);
	}

	uint8_t getCurrentInstructionSize() {
		return getInstructionSize(m_ip);
	}

	uint8_t getInstructionSize(uint64_t ip) {
		opcode op = getOp(ip);
		if (op < OP_RET) {
			return 1;
		} else if (op == OP_RET) {
			return 2;
		} else {
			return -1;
		}
	}

	bool isValidOp(opcode op) {
		return op < OP_MAXDEFINED;
	}

	void printBreakpoints() {
		std::cout << "Breakpoints:\n";
		for(uint64_t i = 0; i < m_breakpoints.size(); i++) {
			if(m_breakpoints[i]) {
				std::cout << i << '\n';
			}
		}
		std::cout << std::flush;
	}

	void printCounts() {
		std::cout << "Counts:\n";
		for(uint16_t i = 0; i < m_hitcounts.size(); i++) {
			uint64_t count = m_hitcounts[i];
			if(count) {
				std::cout << opcode_names[i] << ": " << count << '\n';
			}
		}
	}
private:
	uint64_t m_ip;

	std::vector<opcode> m_buffer;
	std::array<uint64_t, 1 << (8 * sizeof(opcode))> m_hitcounts;
	std::vector<bool> m_breakpoints;
};

class ReaderCLI {
public:
	using CommandArgs = const std::vector<std::string>;
	using CommandFn = std::function<void(CommandArgs& args)>;
	struct Command {
		std::string name;
		CommandFn fn;
	};

	ReaderCLI() :
		m_running(false),
		m_prompt("> "),
		m_info("")
	{}

	CommandFn getInfoCommand(std::function<void()> fn) {
		return [this, fn](CommandArgs& args) {
			fn();
			info();
		};
	}

	CommandFn getInfoCommand(std::function<void(CommandArgs&)> fn) {
		return [this, fn](CommandArgs& args) {
			fn(args);
			info();
		};
	}

	CommandFn getCommand(std::function<void()> fn) {
		return [this, fn](CommandArgs& args) {
			fn();
		};
	}

	bool init() {
		if(!m_reader.load("out_primary.log")) {
			std::cerr << "Can't open file out_primary.log" << std::endl;
			return false;
		}

		using namespace std::placeholders;

		addCommand("s", getInfoCommand([this]() { m_reader.step(); }));
		addCommand("c", getInfoCommand([this]() { m_reader.cont(); }));
		addCommand("f", getInfoCommand([this]() { m_reader.finish(); }));
		addCommand("counts", getCommand([this]() { m_reader.printCounts(); }));
		addCommand("bps", getCommand([this]() { m_reader.printBreakpoints(); }));
		addCommand("dis", std::bind(&ReaderCLI::disassemble, this, _1));
		addCommand("raw", std::bind(&ReaderCLI::raw, this, _1));
		addCommand("info", std::bind(&ReaderCLI::infoFn, this, _1));
		addCommand("quit", std::bind(&ReaderCLI::quit, this, _1));
		return true;
	}

	void disassemble(CommandArgs& args) {
		if(args.size() > 2) {
			std::cerr << "disassemble takes 0, 1, or 2 args" << std::endl;
			return;
		}
		uint64_t ip;
		uint64_t count;
		if(args.size() == 0) {
			ip = m_reader.getIp();
			count = 10;
		} else if(args.size() == 1) {
			std::stringstream ss(args[0]);
			ip = m_reader.getIp();
			if(!(ss >> count)) {
				std::cerr << "Error: invalid count: " << args[0];
				return;
			}
		} else {
			std::stringstream ss(args[0]);
			if(!(ss >> ip)) {
				std::cerr << "Error: invalid ip: " << args[0];
				return;
			}
			ss = std::stringstream(args[1]);
			if(!(ss >> count)) {
				std::cerr << "Error: invalid count: " << args[1];
				return;
			}
		}
		while(count && ip < m_reader.getNumOps()) {
			auto s = m_reader.push(ip);
			m_reader.print("%i: %o\n");
			m_reader.pop(s);
			ip += m_reader.getInstructionSize(ip);
			count--;
		}
	}

	void raw(CommandArgs& args) {
		if(args.size() > 2) {
			std::cerr << "raw takes 0, 1, or 2 args" << std::endl;
			return;
		}
		uint64_t ip;
		uint64_t count;
		if(args.size() == 0) {
			ip = m_reader.getIp();
			count = 10;
		} else if(args.size() == 1) {
			std::stringstream ss(args[0]);
			ip = m_reader.getIp();
			if(!(ss >> count)) {
				std::cerr << "Error: invalid count: " << args[0];
				return;
			}
		} else {
			std::stringstream ss(args[0]);
			if(!(ss >> ip)) {
				std::cerr << "Error: invalid ip: " << args[0];
				return;
			}
			ss = std::stringstream(args[1]);
			if(!(ss >> count)) {
				std::cerr << "Error: invalid count: " << args[1];
				return;
			}
		}
		while(count && ip < m_reader.getNumOps()) {
			std::cout << (uint64_t)m_reader.getOp(ip) << '\n';
			ip++;
			count--;
		}
		std::cout << std::flush;
	}

	void infoFn(CommandArgs& args) {
		if(args.size() == 0) {
			std::cout << std::quoted(m_info) << std::endl;
		} else if(args.size() == 1){
			m_info = args[0];
			std::cout << "info string set to " << std::quoted(m_info) << std::endl;
		} else {
			std::cerr << "invalid number of args: " << args.size();
		}
	}

	void quit(CommandArgs& args) {
		m_running = false;
	}

	void addCommand(std::string name, CommandFn fn) {
		m_commands.push_back({name, fn});
	}

	bool run() {
		m_running = true;

		std::string line;
		std::string lastLine;
		std::stringstream ss;
		std::string command;

		std::vector<std::string> args;

		prompt();
		while (m_running && std::getline(std::cin, line)) {
			command.clear();
			ss = std::stringstream(line);
			if(!(ss >> command)) {
				ss = std::stringstream(lastLine);
				ss >> command;
			} else {
				lastLine = line;
			}

			if(!command.empty()) {
				bool found = false;
				for (auto &c: m_commands) {
					if(c.name == command) {
						found = true;
						args.clear();
						while(ss >> std::quoted(command)) {
							args.push_back(command);
						}
						c.fn(args);
						break;
					}
				}
				if(!found) {
					std::cerr << "Command " << command << " not found" << std::endl;
				}
			}

			prompt();
		}
			
		return true;
	}

	void info() {
		m_reader.print(m_info);
	}

	void prompt() {
		m_reader.print(m_prompt);
	}

	void setInfo(std::string info) {
		m_info = info;
	}

	void setPrompt(std::string prompt) {
		m_prompt = prompt;
	}

private:
	Reader m_reader;
	bool m_running;

	std::string m_info;
	std::string m_prompt;

	std::vector<Command> m_commands;
};

int main() {
	ReaderCLI cli;
	if (!cli.init()) {
		return 1;
	}
	bool success = cli.run();
	return success ? 0 : 1;

	//char last_cmd = '\n';
	//auto readCommand = [&]() -> void {
	//char cmd;
	//std::stringstream ss;
	//std::string line;
	//
	//while(getline(line)) {
	//ss = std::stringstream(line);
	//if((!ss.get(cmd))) {
	//cmd = last_cmd;
	//} else if(cmd != '\n'){
	//last_cmd = cmd;
	//} else {
	//cmd = last_cmd;
	//}
	//
	//switch(cmd) {
	//case '\n':
	//continue;
	//case 's': {
	//uint64_t temp_pc = pc;
	//if(op == 254) {
	//temp_pc += 2;
	//} else if (op < OP_MAXDEFINED) {
	//temp_pc += 1;
	//}
	//breakpoints[temp_pc] = true;
	//return;
	//}
	//case 'c': {
	//std::cout << "Counts:\n";
	//for(uint8_t i = 0; i < sizeof(uint8_t); i++) {
	//uint64_t count = hitcounts[i];
	//if(count) {
	//std::cout << opcode_names[i] << ": " << count << '\n';
	//}
	//}
	//std::cout << std::flush;
	//}
	//case 'n': {
	//uint64_t temp_pc = pc;
	//for(; buffer[pc] < OP_MAXDEFINED && temp_pc < size; temp_pc++);
	//if(temp_pc < size) {
	//breakpoints[temp_pc] = true;
	//}
	//break;
	//}
	//case 'r': {
	//pc = 0;
	//scheduling_pc = 0;
	//std::fill(breakpoints.begin(), breakpoints.end(), false);
	//return;
	//}
	//case 'b': {
	//uint64_t break_pc;
	//if(!(ss >> break_pc)) {
	//std::cerr << "invalid pc to break on" << std::endl;
	//			}
	//			breakpoints[break_pc] = true;
	//			continue;
	//		}
	//		case 'd': {
	//			uint64_t break_pc;
	//			if(!(ss >> break_pc)) {
	//				std::cerr << "invalid pc to not break on" << std::endl;
	//			}
	//			breakpoints[break_pc] = false;
	//			continue;
	//		}
	//		case 'q': {
	//			running = false;
	//			return;
	//		}
	//		default:
	//			std::cerr << "Unrecognized command: " << cmd << std::endl;
	//			continue;
	//		}
	//	}
	//};

	//std::cout << "OP_MAXDEFINED = " << OP_MAXDEFINED << std::endl;
	//while(running) {
	//	readCommand();
	//  	while(pc < size) {
	//		op = buffer[pc];
	//		if(breakpoints[pc]){
	//			readCommand();
	//		}
	//		pc++;
	//		hitcounts[op]++;
	//		if(op < OP_MAXDEFINED) {
	//			std::cout << pc << ": " << opcode_names[op] << '\n';
	//		} else if(op == 254) {
	//			uint64_t pc_scheduled_by;
	//			if(pc < size) {
	//				pc_scheduled_by = buffer[pc++];
	//				std::cout << "RET, pc = " << pc_scheduled_by << '\n';
	//			} else {
	//				std::cerr << "Error reading pc" << std::endl;
	//				return 1;
	//			}
	//		} else {
	//			std::cerr << "Error: incorrect op: " << (int)op << std::endl;
	//			return 1;
	//		}
	//	}
	//}
	//std::cout << "Final pc: " << pc << std::endl;
	//file.close();
}
