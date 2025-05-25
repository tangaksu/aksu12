<?php
// WP Super Shield 自动化功能测试脚本
// 使用：将本文件放入插件根目录，激活插件后访问 http(s)://yourdomain/wp-super-shield-test.php

define('WP_USE_THEMES', false);
require_once(dirname(__FILE__) . '/wp-load.php');

header('Content-Type: text/plain; charset=utf-8');

echo "=== WP Super Shield 自动化测试 ===\n\n";

global $wpdb;
$table = $wpdb->prefix . 'wpss_logs';

// 1. 测试日志表创建
echo "1. 日志表测试: ";
if ($wpdb->get_var("SHOW TABLES LIKE '$table'") == $table) {
    echo "√ 存在\n";
} else {
    echo "× 不存在\n";
}

// 2. 测试日志写入
echo "2. 日志插入测试: ";
$wpdb->insert($table, [
    'ip'=>'127.0.0.1',
    'type'=>'test',
    'msg'=>'自动化测试日志',
    'ua'=>'WPSS-TEST',
    'url'=>'/wp-super-shield-test.php',
    'time'=>current_time('mysql')
]);
$id = $wpdb->insert_id;
if ($id) {
    echo "√ 日志ID: $id\n";
} else {
    echo "× 失败\n";
}

// 3. 测试日志读取
echo "3. 日志读取测试: ";
$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id=%d", $id), ARRAY_A);
if ($row && $row['msg'] === '自动化测试日志') {
    echo "√ 内容: {$row['msg']}\n";
} else {
    echo "× 失败\n";
}

// 4. 测试IP黑名单
echo "4. IP黑名单机制: ";
update_option('wpss_ip_blacklist', "127.0.0.1\n");
require_once plugin_dir_path(__FILE__) . 'includes/iplist.php';
ob_start();
wpss_iplist_defend();
$out = ob_get_clean();
if (strpos($out, 'IP Blacklisted') !== false) {
    echo "√ 拦截\n";
} else {
    echo "× 未拦截（如未终止脚本）\n";
}
update_option('wpss_ip_blacklist', "");

// 5. 测试CC防御（伪请求）
echo "5. CC防御算法: ";
$key = 'wpss_cc_' . md5('127.0.0.1');
delete_transient($key);
require_once plugin_dir_path(__FILE__) . 'includes/cc.php';
for ($i=1; $i<=65; $i++) {
    ob_start();
    wpss_cc_defend();
    $o = ob_get_clean();
    if (strpos($o, 'CC Blocked') !== false || strpos($o, 'Too Many Requests') !== false) {
        echo "√ 第{$i}次已拦截\n";
        break;
    }
}
if ($i < 65) {
    // 被拦截
} else {
    echo "× 未拦截\n";
}

// 6. 测试文件上传拦截
echo "6. 文件上传拦截: ";
$_FILES = [
    'file' => [
        'name' => 'evil.php',
        'type' => 'application/x-php',
        'tmp_name' => tempnam(sys_get_temp_dir(), 'wpss'),
        'error' => 0,
        'size' => 16,
    ]
];
file_put_contents($_FILES['file']['tmp_name'], '<?php echo 1; ?>');
require_once plugin_dir_path(__FILE__) . 'includes/upload.php';
try {
    ob_start();
    wpss_upload_defend($_FILES['file']);
    $out = ob_get_clean();
    echo strpos($out, 'Forbidden Extension') !== false || strpos($out, 'PHP Script Blocked') !== false
        ? "√ 被拦截\n" : "× 未拦截\n";
} catch (Exception $e) {
    echo "× 异常：" . $e->getMessage() . "\n";
}
unlink($_FILES['file']['tmp_name']);

// 7. 恢复测试环境
delete_option('wpss_ip_blacklist');
delete_transient($key);

// 8. 总结
echo "\n=== 测试结束 ===\n";