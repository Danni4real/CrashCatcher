#ifndef CRASH_CATCHER_H
#define CRASH_CATCHER_H

#include <elf.h>
#include <link.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <csignal>
#include <fcntl.h>
#include <unistd.h>
#include <execinfo.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <mutex>
#include <regex>
#include <string>
#include <chrono>
#include <iostream>
#include <exception>

// make sure 1.it already exists; 2.program have permission(rwx) to it;
#define CrashCatcherWorkspacePath "/tmp/"

// these are signals, which will cause program to terminate
// remove signal from this set if you have new signal handler for it
inline int CRASH_CATCHER_SIG_SET[] = {
    SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP,
    SIGABRT, SIGBUS, SIGFPE, SIGSEGV, SIGPIPE,
    SIGALRM, SIGTERM, SIGSTKFLT, SIGXCPU, SIGXFSZ,
    SIGVTALRM, SIGPROF, SIGIO, SIGPWR, SIGSYS
};

class CrashCatcher {
public:
    static void Register(const std::function<void()> &call_before_crash = {}) {
        static std::mutex mtx;
        static bool registered = false;

        std::scoped_lock lk(mtx);
        if (registered) {
            std::cout << "CrashCatcher::Register(): can only Call Register once!!!" << std::endl;
            return;
        }

        registered = true;

        struct sigaction sigact{};

        sigact.sa_handler = print_backtrace;
        sigact.sa_flags = SA_RESTART | SA_SIGINFO;

        m_call_before_crash = call_before_crash;

        for (int sig: CRASH_CATCHER_SIG_SET) {
            if (sigaction(sig, &sigact, nullptr) != 0) {
                fprintf(stderr, "error setting signal handler for %d (%s)\n", sig,
                        strsignal(sig));
                exit(EXIT_FAILURE);
            }
        }

        std::set_terminate(handle_exception);

        // throw_test();
        // segmentfault_test();
    }

private:
    inline static std::function<void()> m_call_before_crash{};

    static size_t get_file_size(const char *path) {
        struct stat s{};

        if (stat(path, &s) == -1) {
            fprintf(stderr, "Failed to stat file %s: %s\n", path, strerror(errno));
            return -1;
        }

        return s.st_size;
    }

    // TODO: 1.validate ELF file; 2.figure out actual header size of ELF (malloc);
    static size_t get_elf_size(const char *path) {
        int fd;
        void *ELFheaderdata;
        Elf64_Ehdr *ELFheader;
        size_t elfsize;

        ELFheaderdata = malloc(64);

        fd = open(path, O_RDONLY);
        if (fd == -1) {
            fprintf(stderr, "Failed to open input file %s: %s\n", path,
                    strerror(errno));

            free(ELFheaderdata);
            return -1;
        }

        read(fd, ELFheaderdata, 64);
        ELFheader = (Elf64_Ehdr *) ELFheaderdata;

        elfsize = ELFheader->e_shoff + (ELFheader->e_shnum * ELFheader->e_shentsize);

        close(fd);
        free(ELFheaderdata);

        return elfsize;
    }

    // converts a address in memory to its VMA address in the executable file
    static size_t mem2vma(size_t mem_addr) {
        Dl_info dl_info;
        link_map *link_map;

        dladdr1((void *) mem_addr, &dl_info, (void **) &link_map, RTLD_DL_LINKMAP);

        return mem_addr - link_map->l_addr;
    }

    static std::string run_cmd(const std::string &cmd) {
        std::string run_result;

        FILE *pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            std::cerr << "run_cmd() failed: " << cmd << std::endl;
            return run_result;
        }

        char buf[1024] = {0};
        while (fgets(buf, sizeof(buf), pipe) != nullptr) run_result += buf;

        pclose(pipe);

        return run_result;
    }

    static void untar(const std::string &src, const std::string &des) {
        char cmd[1024] = {0};

        snprintf(cmd, sizeof(cmd), "tar -xvf %s -C %s >/dev/null 2>&1", src.c_str(),
                 des.c_str());

        run_cmd(cmd);
    }

    static void mkdir(const std::string &path) {
        char cmd[1024] = {0};

        snprintf(cmd, sizeof(cmd), "mkdir %s", path.c_str());

        run_cmd(cmd);
    }

    static void rm(const std::string &path) {
        char cmd[1024] = {0};

        snprintf(cmd, sizeof(cmd), "rm -rf %s", path.c_str());

        run_cmd(cmd);
    }

    // extract compressed project folder from elf file
    static void extract_appendix(const char *elf_path, const char *tar_path) {
        size_t elf_size = get_elf_size(elf_path);
        size_t file_size = get_file_size(elf_path);
        size_t append_size = file_size - elf_size;

        if (append_size > 0) {
            FILE *fp_elf = fopen(elf_path, "rb");
            FILE *fp_tar = fopen(tar_path, "w");

            if (fp_elf == nullptr) {
                printf("Unable to open %s for reading: %s", elf_path, strerror(errno));
                goto end;
            }
            if (fp_tar == nullptr) {
                printf("Unable to open %s for writing: %s", tar_path, strerror(errno));
                goto end;
            }

            fseek(fp_elf, static_cast<long>(elf_size), SEEK_SET);

            char ch;
            while (fread(&ch, 1, 1, fp_elf)) fwrite(&ch, 1, 1, fp_tar);

        end:
            if (fp_elf != nullptr) {
                fclose(fp_elf);
            }
            if (fp_tar != nullptr) {
                fclose(fp_tar);
            }
        }
    }

    // return CrashCatcher.h relative path
    static std::string get_relative_header_path(const char *local_proj_path) {
        std::string path = __FILE__;
        std::string header_name = path.substr(path.find_last_of('/') + 1);

        char cmd[1024] = {0};
        snprintf(cmd, sizeof(cmd), "cd %s;find . -name %s", local_proj_path,
                 header_name.c_str());

        std::string result = run_cmd(cmd);

        result = result.substr(2, result.size() - 3); // strip "./" and newline char

        return result;
    }

    // return project path at compiling machine
    static std::string get_remote_proj_path(const std::string &relative_header_path) {
        std::string str = __FILE__;
        const std::string &sub_str = relative_header_path;

        size_t pos = str.find(sub_str);

        if (pos != std::string::npos) str.erase(pos, sub_str.length());

        return str;
    }

    // generate project path at executing machine
    static std::string gen_local_proj_path() {
        using namespace std::chrono;

        std::string path = CrashCatcherWorkspacePath;

        uint64_t now =
                duration_cast<nanoseconds>(system_clock::now().time_since_epoch())
                .count();

        path += std::to_string(now);

        mkdir(path);

        return path;
    }

    static void print_backtrace(int) {
        static std::mutex lock;
        std::unique_lock<std::mutex> l(lock, std::try_to_lock);
        if (!l.owns_lock()) {
            return;
        }

        void *callstack[1024];
        int frame_count =
                backtrace(callstack, sizeof(callstack) / sizeof(callstack[0]));

        Dl_info dl_info;
        if (dladdr(callstack[0], &dl_info) == 0) exit(0);

        const char *bin_path = dl_info.dli_fname;
        std::cout << bin_path << " crashed!!!";

        std::string local_proj_path = gen_local_proj_path();
        std::string tar_path = local_proj_path + "/code.tar.gz";

        extract_appendix(bin_path, tar_path.c_str());

        bool src_files_attached = false;
        if (access(tar_path.c_str(), F_OK) == 0)
            src_files_attached = true;

        std::string remote_proj_path;

        if (src_files_attached) {
            untar(tar_path, local_proj_path);

            remote_proj_path =
                    get_remote_proj_path(
                        get_relative_header_path(
                            local_proj_path.c_str()));
        }


        std::cout << "\n\nBacktrace raw:\n";
        char **backtrace = backtrace_symbols(callstack, frame_count);
        for (int i = 0; i < frame_count; i++) {
            std::cout << backtrace[i] << std::endl;
        }

        std::cout << "\n\nBacktrace detail:";
        for (int i = 2; i < frame_count - 3; i++) {
            char cmd[1024] = {0};
            size_t vma_addr = mem2vma((size_t) callstack[i]) - 1;

            if (src_files_attached) {
                snprintf(cmd, sizeof(cmd),
                         "cd %s;"
                         "addr2line -e %s -Ci %zx 2>&1 | while read line;"
                         "do s_l=${line#%s};"
                         "s=${s_l%%:*};"
                         "l=${s_l#*:};"
                         "echo $s_l;"
                         "head -n $l $s | tail -1;echo '';"
                         "done",
                         local_proj_path.c_str(), bin_path, vma_addr,
                         remote_proj_path.c_str());
            } else {
                snprintf(cmd, sizeof(cmd),
                         "addr2line -e %s -Cif %zx 2>&1",
                         bin_path, vma_addr);
            }

            std::cout << std::endl << run_cmd(cmd);
        }

        rm(local_proj_path);

        if (m_call_before_crash)
            m_call_before_crash();

        kill(getpid(), SIGKILL);
    }

    static void handle_exception() {
        print_backtrace(0);
    }

    static void segmentfault_test() {
        int *x = 0;
        *x = 0;
    }

    static void throw_test() {
        throw 100;
    }
};

#endif
