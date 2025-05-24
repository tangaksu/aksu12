<?php
if (!defined('ABSPATH')) exit;

// 插件基础设置页面（含IP黑白名单）
function aksu_settings_page() {
    if (isset($_POST['wpss_settings_save']) && check_admin_referer('wpss_settings')) {
        update_option('wpss_admin_email', sanitize_email($_POST['wpss_admin_email']));
        update_option('wpss_log_display_count', max(1, intval($_POST['wpss_log_display_count'])));
        update_option('wpss_log_retention_days', max(1, intval($_POST['wpss_log_retention_days'])));
        update_option('wpss_ip_whitelist', trim($_POST['wpss_ip_whitelist']));
        update_option('wpss_ip_blacklist', trim($_POST['wpss_ip_blacklist']));
        echo '<div class="updated"><p>基础设置已保存。</p></div>';
    }
    $display_count = intval(get_option('wpss_log_display_count', 30));
    $retention_days = intval(get_option('wpss_log_retention_days', 30));
    $white = get_option('wpss_ip_whitelist', '');
    $black = get_option('wpss_ip_blacklist', '');
    ?>
    <div class="wrap">
        <h1>插件设置</h1>
        <form method="post">
            <?php wp_nonce_field('wpss_settings'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="wpss_admin_email">安全通知邮箱</label></th>
                    <td>
                        <input type="email" name="wpss_admin_email" id="wpss_admin_email" value="<?php echo esc_attr(get_option('wpss_admin_email', get_option('admin_email'))); ?>" size="40">
                        <p class="description">当有重要拦截或操作时，将邮件通知此邮箱。</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="wpss_log_display_count">仪表盘显示日志条数</label></th>
                    <td>
                        <input type="number" min="1" name="wpss_log_display_count" id="wpss_log_display_count" value="<?php echo esc_attr($display_count); ?>" style="width:80px;">
                        <p class="description">仪表盘页面最新安全日志展示的记录条数。</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="wpss_log_retention_days">日志保存天数</label></th>
                    <td>
                        <input type="number" min="1" name="wpss_log_retention_days" id="wpss_log_retention_days" value="<?php echo esc_attr($retention_days); ?>" style="width:80px;">
                        <p class="description">安全日志最长保存天数，超出天数的日志将自动清理。</p>
                    </td>
                </tr>
                <tr>
                    <th>IP白名单</th>
                    <td>
                        <textarea name="wpss_ip_whitelist" rows="5" cols="60" placeholder="每行填写一个IP或通配符"><?php echo esc_textarea($white); ?></textarea>
                        <p class="description">支持如 192.168.1.1 或 192.168.*.*，支持IPV6。白名单IP将永不拦截。</p>
                    </td>
                </tr>
                <tr>
                    <th>IP黑名单</th>
                    <td>
                        <textarea name="wpss_ip_blacklist" rows="5" cols="60" placeholder="每行填写一个IP或通配符"><?php echo esc_textarea($black); ?></textarea>
                        <p class="description">支持如 1.2.3.4、10.10.*.*、2001:db8::1等。命中黑名单将直接拒绝访问。</p>
                    </td>
                </tr>
            </table>
            <p><button type="submit" class="button button-primary" name="wpss_settings_save">保存设置</button></p>
        </form>
    </div>
    <?php
}