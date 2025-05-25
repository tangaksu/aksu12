<?php
// aksu defense - 文件上传拦截模块
if (!defined('ABSPATH')) exit;

if (!function_exists('aksu_upload_defend')) {
    function aksu_upload_defend() {
        // 管理员豁免：已登录且为管理员账号直接放行
        if (function_exists('is_user_logged_in') && function_exists('current_user_can')) {
            if (is_user_logged_in() && current_user_can('manage_options')) return;
        }

        if (!get_option('wpss_fw_upload_status', 1)) return;
        // 阻止上传PHP脚本
        $block_php = get_option('wpss_fw_php_script_status', 1);

        // 大数据增强：常见Webshell、危险扩展、MIME类型等黑名单
        $dangerous_exts = [
            'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'asp', 'aspx', 'jsp', 'jspx', 'exe', 'sh', 'bat', 'cmd', 'pl', 'py', 'rb', 'cgi', 'dll', 'so', 'bin', 'js', 'jar', 'wsf', 'vbs', 'scr', 'msi', 'com'
        ];
        $dangerous_mimes = [
            'application/x-php', 'application/x-httpd-php', 'text/x-php', 'application/x-msdownload', 'application/x-sh', 'application/x-csh', 'application/javascript', 'application/x-javascript', 'text/javascript', 'application/x-msdos-program',
            'application/octet-stream', 'text/html', 'text/x-shellscript', 'application/x-powershell', 'application/x-python-code', 'text/x-python', 'application/java-archive'
        ];

        foreach ($_FILES as $file) {
            if (empty($file['name'])) continue;
            $filename = strtolower($file['name']);

            // 1. 检查危险扩展名
            $ext = pathinfo($filename, PATHINFO_EXTENSION);
            if (in_array($ext, $dangerous_exts)) {
                if (function_exists('wpss_log')) wpss_log('upload', "危险扩展名文件上传拦截: $filename");
                aksu_defense_die('Blocked file upload', 403);
            }

            // 2. 检查危险MIME类型
            if (!empty($file['type']) && in_array(strtolower($file['type']), $dangerous_mimes)) {
                if (function_exists('wpss_log')) wpss_log('upload', "危险MIME类型文件上传拦截: $filename, 类型: " . $file['type']);
                aksu_defense_die('Blocked file upload', 403);
            }

            // 3. 阻止双扩展名（如 shell.php.jpg、1.jpg.php）
            if (preg_match('/\.(jpg|jpeg|png|gif|bmp|webp|svg|pdf|txt)\.(php[0-9]?|phtml|phar|asp|aspx|jsp|exe|sh|bat|cmd|pl|py|rb|cgi|dll|so|bin|js|jar|wsf|vbs|scr|msi|com)$/i', $filename)) {
                if (function_exists('wpss_log')) wpss_log('upload', "双扩展名文件上传拦截: $filename");
                aksu_defense_die('Blocked file upload', 403);
            }

            // 4. 检查文件内容是否包含PHP/webshell/恶意代码特征
            if (is_uploaded_file($file['tmp_name'])) {
                $content = @file_get_contents($file['tmp_name'], false, null, 0, 2048); // 只读前2K，提高效率
                // 检查PHP代码特征
                if (preg_match('/<\?(php|=)?[\s\r\n]/i', $content) ||
                    preg_match('/(eval\s*\(|assert\s*\(|base64_decode\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|exec\s*\(|popen\s*\(|proc_open\s*\()/i', $content)) {
                    if (function_exists('wpss_log')) wpss_log('upload', "文件内容含PHP/webshell代码拦截: $filename");
                    aksu_defense_die('Blocked file upload', 403);
                }
                // 检查HTML/JS等内容型攻击
                if (preg_match('/<script[\s>]/i', $content) || preg_match('/onerror\s*=/i', $content)) {
                    if (function_exists('wpss_log')) wpss_log('upload', "文件内容含HTML/JS危险代码拦截: $filename");
                    aksu_defense_die('Blocked file upload', 403);
                }
            }
        }
    }
    add_action('init', 'aksu_upload_defend', 8);
}