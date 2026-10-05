// main.cpp - CLI entry: argument parsing, selftest, signal handling
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "dialer.h"
#include "util.h"
#include "zsm/damod.h"

using namespace ty;

static void onSignal(int) { gStop = 1; }

static int usage() {
    printf("tylogin-native - 江苏电信校园网（天翼校园宽）独立登录客户端（C++ 原生版）\n");
    printf("\n");
    printf("用法: tylogin [选项]\n");
    printf("\n");
    printf("  -u <账号> -p <密码>     指定账号密码（缺省读取工作目录下 config 文件）\n");
    printf("  -l, --loop             与官方客户端一致：持续心跳保活，Ctrl+C 退出时自动下线\n");
    printf("  -d, --debug            输出详细协议日志\n");
    printf("  -h, --help             显示帮助\n");
    printf("\n");
    printf("默认（无 -l）：登录成功后立即退出，会话保持在线至服务端心跳超时。\n");
    printf("\n");
    printf("环境变量:\n");
    printf("  TYLOGIN_HOME           模拟器工作目录（默认 ~/.tylogin）\n");
    printf("  TY_THREAD_SYNC=1       同步执行模拟器内创建的线程（调试用）\n");
    printf("  TY_EMU_TIMEOUT=<秒>    单次模拟执行的看门狗超时\n");
    printf("\n");
    printf("config 文件格式（config / config.txt / tylogin.conf）:\n");
    printf("  account=<账号>\n");
    printf("  password=<密码>\n");
    printf("\n");
    printf("退出码: 0 成功/已在线  1 认证失败  2 网络不可达\n");
    return 0;
}

static int selftest(const char* zsmPath) {
    setDebug(true);
    try {
        std::string home;
        if (getenv("TYLOGIN_HOME")) {
            home = getenv("TYLOGIN_HOME");
        } else {
#ifdef _WIN32
            const char* prof = getenv("USERPROFILE");
            home = std::string(prof ? prof : ".") + "\\.tylogin";
#else
            home = std::string(getenv("HOME") ?: ".") + "/.tylogin";
#endif
        }
        ZsmRuntime zsm("com.cndatacom.campus.cdccportaljs", home);
        info("JNI_OnLoad ok, DaMod natives registered");

        std::vector<uint8_t> mod;
        if (zsmPath && readFile(zsmPath, mod)) {
            info("loading ZSM module: " + std::string(zsmPath) + " (" +
                 std::to_string(mod.size()) + " bytes)");
            int64_t h = zsm.load(mod);
            if (h == 0) {
                err("ZSM module load 失败 (返回 0)");
                return 1;
            }
            std::string aid = zsm.algoId(h);
            std::string key = zsm.sessionKey(h);
            std::string prev = zsm.prefix(h);
            info("session=" + std::to_string(h));
            info("aid  = " + aid);
            info("key  = " + key);
            info("prev = " + prev);
            // enc/dec roundtrip
            std::string xml = std::string("<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                                          "<request><client-id>selftest</client-id></request>");
            std::string enc = zsm.encrypt(h, xml);
            info("enc(" + std::to_string(xml.size()) + "B) = " + enc.substr(0, 64) + "… (" +
                 std::to_string(enc.size()) + " hex chars)");
            std::string dec = zsm.decrypt(h, enc);
            if (dec == enc) {
                err("dec roundtrip 异常: dec==enc");
            } else if (dec.find("</request>") != std::string::npos) {
                info("dec roundtrip ok: " + dec);
            } else {
                info("dec roundtrip result: " + dec);
            }
            zsm.freeSession(h);
            info("selftest done");
            return 0;
        }
        // failure-path check: an invalid module must load() to 0 without crashing
        std::vector<uint8_t> garbage(1024, 0xAB);
        int64_t h2 = zsm.load(garbage);
        info(std::string("garbage module load -> ") + (h2 == 0 ? "0 (graceful fail, ok)" :
             ("nonzero " + std::to_string(h2) + " (unexpected)")));
        info("（未提供 ZSM 模块文件，只做了 JNI_OnLoad + 失败路径冒烟）");
        info("用法: tylogin --selftest <damod 文件>");
        return h2 == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        err(std::string("selftest failed: ") + e.what());
        return 1;
    }
}

int main(int argc, char** argv) {
    DialerOptions opt;
    bool haveUser = false, havePass = false;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "-u" && i + 1 < argc) {
            opt.user = argv[++i];
            haveUser = true;
        } else if (a == "-p" && i + 1 < argc) {
            opt.pass = argv[++i];
            havePass = true;
        } else if (a == "-l" || a == "--loop") {
            opt.loop = true;
        } else if (a == "-d" || a == "--debug") {
            setDebug(true);
        } else if (a == "--selftest") {
            return selftest(i + 1 < argc ? argv[++i] : nullptr);
        } else if (a == "--dump-zsm" && i + 1 < argc) {
            DialerOptions dopt;
            return Dialer(dopt).dumpZsm(argv[++i]);
        } else if (a == "-h" || a == "--help") {
            return usage();
        } else {
            err("未知参数 " + a);
            return usage();
        }
    }

    signal(SIGINT, onSignal);
    signal(SIGTERM, onSignal);

    // config file fallback (working directory)
    if (!haveUser || !havePass) {
        std::string cu, cp;
        readConfig(".", cu, cp);
        if (opt.user.empty()) opt.user = cu;
        if (opt.pass.empty()) opt.pass = cp;
    }

    if (opt.user.empty() || opt.pass.empty()) {
        err("未提供账号密码（-u/-p 或 config 文件）");
        return usage();
    }

    Dialer dialer(opt);
    int rc = dialer.loginOnce();
    if (!opt.loop) return rc;
    // loop mode: fall through on any first-login result; runLoop's relogin
    // loop retries (hasKeepSession() guards against keeping without a session)
    return dialer.runLoop();
}
