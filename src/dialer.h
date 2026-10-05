// dialer.h - Jiangsu ESurfing portal client state machine (port of JSDialer.kt)
#pragma once
#include <csignal>
#include <string>

#include "http.h"

namespace ty {

extern volatile sig_atomic_t gStop;  // set by the SIGINT/SIGTERM handler

struct DialerOptions {
    std::string user, pass;
    bool loop = false;
};

class Dialer {
public:
    explicit Dialer(const DialerOptions& opt);

    // one full login attempt; returns process exit code (0/1/2)
    int loginOnce();

    // download the ZSM module (zero Algo-ID) and save it to path (offline testing)
    int dumpZsm(const std::string& path);

    // loop mode: heartbeat until stop flag; auto re-login on failure;
    // sends term (reason=1) on exit like the official client
    int runLoop();

private:
    enum PortalState { ONLINE, PORTAL, UNREACHABLE };

    // keep-alive outcome classification (port of JSDialer.KeepOutcome)
    struct KeepOutcome {
        enum Kind { OK, PROTO_FAIL, NET_FAIL };
        Kind kind = OK;
        std::string code, sub;  // PROTO_FAIL: Error-Code / Sub-Error
        std::string errMsg;     // NET_FAIL: exception text
    };

    PortalState discoverPortal();
    bool initCrypto();
    bool ticketRequest();
    // returns nullptr on success, static error text otherwise
    const char* auth(const std::string& user, const std::string& pass);
    KeepOutcome keepOnce();
    KeepOutcome keepWithRetry();
    bool hasKeepSession() const;
    bool quickPortalProbe();
    bool sleepWithProbe(long totalSec);
    void term(const std::string& reason = "1");
    void resetSession();
    HttpResp post(const std::string& url, const std::string& body);

    DialerOptions opt_;
    std::string clientId_;
    std::string algoId_;
    void* session_ = nullptr;  // opaque ZsmRuntime session handle

    // network identity from BAS redirect
    std::string wlanUserIp_, mscgIp_, wlanUserMac_, userLocation_;
    // portal urls from index.cgi
    std::string ticketUrl_, authUrl_;
    std::string delDomainVal_;  // valid only when hasDelDomain_
    bool hasDelDomain_ = false;
    // session state
    std::string ticket_, keepUrl_, termUrl_;
    long keepInterval_ = 60;
    // last failure detail while probing the portal (for user-facing errors)
    std::string portalError_;
};

// errCode -> friendly text (Chinese), ported from JSDialer.errCodeText
std::string errCodeText(const std::string& code);

}  // namespace ty
