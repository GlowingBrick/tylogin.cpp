#!/usr/bin/env bash
# realtest.sh - 校园网真机一键验证脚本（需要未认证状态 + @f-Young 已连接）
#
# 用法:
#   tools/realtest.sh                 # 只做模块抓取 + 模拟器对拍（不需要账号）
#   tools/realtest.sh --login         # 对拍通过后用 ./config 或 -u/-p 真实登录
#   tools/realtest.sh -u 账号 -p 密码 --login --keep
#
# 流程:
#   1. 检查门户状态: check.go189.cn 返回 302 = 未认证(可测)；200 = 已在线(先断开)
#   2. --dump-zsm  抓取服务端下发的 ZSM 算法模块
#   3. --selftest  用真实模块对拍 aid/key/prev + enc/dec roundtrip
#   4. --login     真实登录（可选 --keep 进入保活模式）
set -u
cd "$(dirname "$0")/.."
BIN=./build/tylogin
# ZSM 模块静态特征（aid 的前 8 位是服务端下发时间戳，逐次不同）
EXP_AID_SUFFIX="50fa-11f0-b040-fa163efce7ed"
EXP_PREV="001"

USER_ARG=(); DO_LOGIN=0; DO_KEEP=0; MODULE=./damod.bin; WAIT=0
while [ $# -gt 0 ]; do
    case "$1" in
        -u) USER_ARG+=(-u "$2"); shift 2 ;;
        -p) USER_ARG+=(-p "$2"); shift 2 ;;
        --login) DO_LOGIN=1; shift ;;
        --keep) DO_KEEP=1; DO_LOGIN=1; shift ;;
        --module) MODULE="$2"; shift 2 ;;
        --wait) WAIT=1; shift ;;   # 已在线时轮询等待掉线
        *) echo "unknown arg $1"; exit 2 ;;
    esac
done

[ -x "$BIN" ] || { echo "先构建: ninja -C build"; exit 2; }

echo "== 1. 门户状态 =="
if [ -s "$MODULE" ]; then
    echo "模块文件 $MODULE 已存在，跳过状态检查与抓取（离线对拍模式）"
else
code=$(curl -s -m 8 -A "CCTP/android64/3001" -o /dev/null -w "%{http_code}" http://check.go189.cn)
echo "check.go189.cn -> $code  (200=已在线  302=未认证)"
if [ "$code" = "200" ]; then
    if [ "$WAIT" = "1" ]; then
        echo "已在线，等待掉线（每 15s 检查一次，Ctrl+C 放弃）..."
        while :; do
            sleep 15
            code=$(curl -s -m 8 -A "CCTP/android64/3001" -o /dev/null -w "%{http_code}" http://check.go189.cn)
            echo "  -> $code"
            [ "$code" = "302" ] && break
        done
    else
        echo "当前已在线，无法下发算法模块。先断开（Web 注销/等待超时/换设备），"
        echo "或用 --wait 让本脚本轮询等待。"
        exit 1
    fi
fi

echo
echo "== 2. 抓取 ZSM 模块 =="
"$BIN" --dump-zsm "$MODULE" || { echo "模块抓取失败"; exit 1; }
echo "模块大小: $(stat -c%s "$MODULE") 字节"
fi

echo
echo "== 3. 模拟器对拍 =="
OUT=$("$BIN" --selftest "$MODULE" 2>/dev/null)
echo "$OUT"
rc=0
echo "$OUT" | grep -q "$EXP_AID_SUFFIX"         || { echo "!! aid 静态后缀不匹配（期望 *-$EXP_AID_SUFFIX）"; rc=1; }
echo "$OUT" | grep -qE "key  = [0-9A-F]{64}"    || { echo "!! key 不是 64 位 hex"; rc=1; }
echo "$OUT" | grep -q "prev = $EXP_PREV"        || { echo "!! prev 不匹配（期望 $EXP_PREV）"; rc=1; }
echo "$OUT" | grep -q "<sysinfo>"               || { echo "!! enc/dec roundtrip 缺少 sysinfo 注入"; rc=1; }
echo "$OUT" | grep -q "roundtrip ok"            || { echo "!! enc/dec roundtrip 未通过"; rc=1; }
[ $rc -eq 0 ] && echo ">> 对拍全部通过（加密引擎与 Java/unidbg 版兼容）" || {
    echo ">> 对拍失败 —— 加 -d 看 [libc]/[jni]/[logcat] 日志定位；"
    echo "   若疑似线程问题可试: TY_THREAD_SYNC=1 $BIN --selftest $MODULE"
    exit 1
}

echo
echo "== 4. 真实登录 =="
if [ "$DO_LOGIN" = "1" ]; then
    if [ "$DO_KEEP" = "1" ]; then
        exec "$BIN" "${USER_ARG[@]}" -l
    else
        exec "$BIN" "${USER_ARG[@]}"
    fi
else
    echo "（跳过，--login 未指定；账号可放 ./config 或用 -u/-p）"
fi
