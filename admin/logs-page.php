<?php
if (!defined('ABSPATH')) exit;

// 日志管理页面
function aksu_logs_page() {
    global $wpdb;
    $table = $wpdb->prefix . 'wpss_logs';

    // 清理日志
    if (isset($_POST['wpss_logs_clear']) && check_admin_referer('wpss_logs_clear')) {
        $wpdb->query("TRUNCATE TABLE $table");
        echo '<div class="updated"><p>日志已清空。</p></div>';
    }

    // 导出日志
    if (isset($_POST['wpss_logs_export']) && check_admin_referer('wpss_logs_export')) {
        $logs = $wpdb->get_results("SELECT * FROM $table ORDER BY id DESC");
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment;filename="aksu-defense-logs.csv"');
        echo "ID,时间,IP,类型,信息,UA,请求\n";
        foreach ($logs as $log) {
            echo '"' . $log->id . '","' . $log->time . '","' . $log->ip . '","' . $log->type . '","' . str_replace('"', '""', $log->msg) . '","' . str_replace('"', '""', $log->ua) . '","' . str_replace('"', '""', $log->url) . '"' . "\n";
        }
        exit;
    }

    // 分页
    $page = max(1, intval($_GET['paged'] ?? 1));
    $per_page = 30; // 每页30条
    $offset = ($page - 1) * $per_page;
    $total = (int)$wpdb->get_var("SELECT COUNT(*) FROM $table");
    $pages = max(1, ceil($total / $per_page));
    $logs = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table ORDER BY id DESC LIMIT %d OFFSET %d", $per_page, $offset));

    ?>
    <div class="wrap">
        <h1>安全日志</h1>
        <form method="post" style="margin-bottom:16px;display:flex;gap:12px;align-items:center;">
            <?php wp_nonce_field('wpss_logs_export'); ?>
            <button type="submit" class="button" name="wpss_logs_export">导出全部日志</button>
            <?php wp_nonce_field('wpss_logs_clear'); ?>
            <button type="submit" class="button" name="wpss_logs_clear" onclick="return confirm('确定要清空所有日志吗？');">清空全部日志</button>
        </form>
        <table class="widefat fixed">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>时间</th>
                    <th>IP</th>
                    <th>类型</th>
                    <th>信息</th>
                    <th>UserAgent</th>
                    <th>请求</th>
                </tr>
            </thead>
            <tbody>
            <?php
            if ($logs) foreach ($logs as $log) {
                echo '<tr>';
                echo '<td>' . esc_html($log->id) . '</td>';
                echo '<td>' . esc_html($log->time) . '</td>';
                echo '<td>' . esc_html($log->ip) . '</td>';
                echo '<td>' . esc_html($log->type) . '</td>';
                echo '<td>' . esc_html($log->msg) . '</td>';
                echo '<td>' . esc_html($log->ua) . '</td>';
                echo '<td>' . esc_html($log->url) . '</td>';
                echo '</tr>';
            } else {
                echo '<tr><td colspan="7">暂无日志</td></tr>';
            }
            ?>
            </tbody>
        </table>
        <div style="margin:16px 0;">
            <?php
            if ($pages > 1) {
                for ($i = 1; $i <= $pages; $i++) {
                    if ($i == $page) {
                        echo "<span style='padding:4px 10px;background:#2271b1;color:#fff;border-radius:3px;margin-right:5px;'>$i</span>";
                    } else {
                        echo '<a style="padding:4px 10px;border:1px solid #ddd;border-radius:3px;margin-right:5px;" href="'.esc_url(add_query_arg('paged', $i)).'">'.$i.'</a>';
                    }
                }
            }
            ?>
        </div>
    </div>
    <?php
}