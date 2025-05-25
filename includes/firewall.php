<?php
// aksu defense - 防火墙核心函数（智能增强版）
// 参考主流WAF防护、WordPress安全最佳实践，兼容插件所有拦截与钩子

if (!defined('ABSPATH')) exit;

/**
 * 智能防火墙拦截终止函数
 * @param string $msg 响应体内容（给用户/攻击者的提示）
 * @param int $code HTTP状态码，403为默认
 * @param array $extra_headers 可扩展自定义响应头
 * @return void
 */
function aksu_defense_die($msg = 'Access Denied', $code = 403, $extra_headers = []) {
    // 1. 标准响应头
    status_header($code);
    header('Content-Type: text/plain; charset=utf-8');

    // 2. 安全响应头，阻止浏览器误执行
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');

    // 3. 防止缓存
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');

    // 4. 自定义扩展响应头（如有）
    if (is_array($extra_headers)) {
        foreach ($extra_headers as $k => $v) {
            header("$k: $v");
        }
    }

    // 5. 兼容主流安全设备/日志分析系统（可选，含唯一拦截标识）
    header('X-Aksu-Firewall: Blocked');

    // 6. 记录详细日志（如插件已接入日志模块且未重复记）
    if (function_exists('wpss_log') && !defined('AKSU_DEFENSE_DIE_LOGGED')) {
        define('AKSU_DEFENSE_DIE_LOGGED', 1);
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $url = $_SERVER['REQUEST_URI'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $type = 'firewall';
        $info = "拦截: {$msg} | IP: {$ip} | UA: {$ua} | URL: {$url} | REF: {$referer}";
        wpss_log($type, $info, $url, $ua);
    }

    // 7. 输出响应内容（防止多余HTML）
    echo $msg;
    exit;
}