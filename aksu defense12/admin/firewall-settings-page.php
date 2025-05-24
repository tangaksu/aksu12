<?php
if (!defined('ABSPATH')) exit;

// 防火墙配置页面
function aksu_firewall_settings_page() {
    if (isset($_POST['wpss_fw_save']) && check_admin_referer('wpss_fw_settings')) {
        update_option('wpss_fw_cc_status', isset($_POST['wpss_fw_cc_status']) ? 1 : 0);
        update_option('wpss_cc_limit', intval($_POST['wpss_cc_limit']));
        // 安全判断，防止未定义警告
        update_option('wpss_cc_period', isset($_POST['wpss_cc_period']) ? intval($_POST['wpss_cc_period']) : get_option('wpss_cc_period', 60));
        update_option('wpss_cc_blocktime', intval($_POST['wpss_cc_blocktime']));
        update_option('wpss_fw_injection_status', isset($_POST['wpss_fw_injection_status']) ? 1 : 0);
        update_option('wpss_fw_useragent_status', isset($_POST['wpss_fw_useragent_status']) ? 1 : 0);
        update_option('wpss_fw_scan_status', isset($_POST['wpss_fw_scan_status']) ? 1 : 0);
        update_option('wpss_fw_cookie_status', isset($_POST['wpss_fw_cookie_status']) ? 1 : 0);
        update_option('wpss_fw_upload_status', isset($_POST['wpss_fw_upload_status']) ? 1 : 0);
        update_option('wpss_fw_php_script_status', isset($_POST['wpss_fw_php_script_status']) ? 1 : 0);
        update_option('wpss_fw_uri_status', isset($_POST['wpss_fw_uri_status']) ? 1 : 0);
        update_option('wpss_fw_uri_custom_status', isset($_POST['wpss_fw_uri_custom_status']) ? 1 : 0);
        update_option('wpss_uri_custom_rules', sanitize_textarea_field($_POST['wpss_uri_custom_rules']));
        update_option('wpss_ua_blacklist', trim($_POST['wpss_ua_blacklist']));
        echo '<div class="updated"><p>设置已保存。</p></div>';
    }
    ?>
    <div class="wrap">
        <h1>防火墙规则设置</h1>
        <form method="post">
            <?php wp_nonce_field('wpss_fw_settings'); ?>
            <table class="form-table">
                <tr>
                    <th>CC攻击防御</th>
                    <td>
                        <label><input type="checkbox" name="wpss_fw_cc_status" value="1" <?php checked(get_option('wpss_fw_cc_status', 1)); ?>> 启用</label><br>
                        单位时间<code>秒</code>内最多 <input type="number" name="wpss_cc_limit" value="<?php echo esc_attr(get_option('wpss_cc_limit', 60)); ?>" style="width:70px;"> 次请求，
                        周期 <input type="number" name="wpss_cc_period" value="<?php echo esc_attr(get_option('wpss_cc_period', 60)); ?>" style="width:70px;"> 秒，
                        封锁 <input type="number" name="wpss_cc_blocktime" value="<?php echo esc_attr(get_option('wpss_cc_blocktime', 1800)); ?>" style="width:70px;"> 秒
                    </td>
                </tr>
                <tr>
                    <th>SQL/XSS注入拦截</th>
                    <td><label><input type="checkbox" name="wpss_fw_injection_status" value="1" <?php checked(get_option('wpss_fw_injection_status', 1)); ?>> 启用</label></td>
                </tr>
                <tr>
                    <th>恶意User-Agent拦截</th>
                    <td>
                        <label><input type="checkbox" name="wpss_fw_useragent_status" value="1" <?php checked(get_option('wpss_fw_useragent_status', 1)); ?>> 启用</label>
                        <br>
                        <label><b>自定义User-Agent黑名单：</b></label><br>
                        <textarea name="wpss_ua_blacklist" rows="2" style="width:70%;" placeholder="*curl*|*IE*|*chrome*|*firefox*"><?php echo esc_textarea(get_option('wpss_ua_blacklist', '')); ?></textarea>
                        <p class="description" style="color:#888;">
                            <b>填写说明：</b>多行填写，每行可用 <code>|</code> 分割多个值，支持通配符 <code>*</code>。
                            <span style="cursor:pointer;color:#2271b1;" onclick="var e=document.getElementById('ua_blacklist_example');e.style.display=e.style.display==='none'?'block':'none';this.blur();return false;">示例</span>
                            <span id="ua_blacklist_example" style="display:none;margin:8px 0 0 0;padding:8px 12px;background:#f6f6f6;border-radius:4px;border:1px solid #eee; color:#444;">
                                <br>- <b>*</b> 代表任意字符串。例如：<code>*crawler*</code> 匹配包含 crawler 的所有UA。<br>
                                - <code>abc*</code> 匹配以 abc 开头的UA。<br>
                                - <code>*abc</code> 匹配以 abc 结尾的UA。<br>
                                - <code>abc</code> 匹配等于 abc 的UA。<br>
                                - <code>*curl*</code> （可拦截包含curl的UA）<br>
                                <code>chrome|firefox</code> （可拦截包含chrome或firefox的UA）<br>
                                <code>BadBot*</code> （可拦截以BadBot开头的UA）<br>
                                - 多个规则用 <code>|</code> 隔开，不要换行。
                            </span>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>敏感路径扫描拦截</th>
                    <td><label><input type="checkbox" name="wpss_fw_scan_status" value="1" <?php checked(get_option('wpss_fw_scan_status', 1)); ?>> 启用</label></td>
                </tr>
                <tr>
                    <th>Cookie注入拦截</th>
                    <td><label><input type="checkbox" name="wpss_fw_cookie_status" value="1" <?php checked(get_option('wpss_fw_cookie_status', 1)); ?>> 启用</label></td>
                </tr>
                <tr>
                    <th>文件上传拦截</th>
                    <td>
                        <label><input type="checkbox" name="wpss_fw_upload_status" value="1" <?php checked(get_option('wpss_fw_upload_status', 1)); ?>> 启用</label>
                        &nbsp;|&nbsp;
                        <label><input type="checkbox" name="wpss_fw_php_script_status" value="1" <?php checked(get_option('wpss_fw_php_script_status', 1)); ?>> 阻止上传PHP脚本</label>
                    </td>
                </tr>
                <tr>
                    <th>URI规则拦截</th>
                    <td>
                        <label><input type="checkbox" name="wpss_fw_uri_status" value="1" <?php checked(get_option('wpss_fw_uri_status', 1)); ?>> 启用路径穿越/敏感字符拦截</label>
                        <br><label><input type="checkbox" name="wpss_fw_uri_custom_status" value="1" <?php checked(get_option('wpss_fw_uri_custom_status', 0)); ?>> 启用自定义URI规则</label>
                        <br>
                        <textarea name="wpss_uri_custom_rules" rows="2" cols="60" placeholder="/example-uri"><?php echo esc_textarea(get_option('wpss_uri_custom_rules', '')); ?></textarea>
                        <p class="description" style="color:#888;">
                            <b>填写说明：</b>每行填写一组规则，同一行内可用 <b>|</b> 分隔多个内容，命中任意一个即拦截。支持关键词与正则表达式混用。
                            <span style="cursor:pointer;color:#2271b1;" onclick="var e=document.getElementById('uri_rules_example');e.style.display=e.style.display==='none'?'block':'none';this.blur();return false;">示例</span>
                            <span id="uri_rules_example" style="display:none;margin:8px 0 0 0;padding:8px 12px;background:#f6f6f6;border-radius:4px;border:1px solid #eee; color:#444;">
                                <br><code>/admin|/manage</code> （命中 /admin 或 /manage 即拦截）<br>
                                <code>.php|.asp</code> （命中 .php 或 .asp 即拦截）<br>
                                <code>/api/v1/</code> （命中 /api/v1/ 即拦截）<br>
                                <code>/^\\/debug\\//</code> （正则，命中以 /debug/ 开头路径即拦截）<br>
                                <b>注意：</b>正则表达式需以 <code>/</code> 开头和结尾，其余为普通关键词匹配。
                            </span>
                        </p>
                    </td>
                </tr>
            </table>
            <p><button class="button button-primary" type="submit" name="wpss_fw_save">保存设置</button></p>
        </form>

        <div class="wpss-section-title" style="margin-top:36px;">拦截时HTTP响应头说明</div>
        <div style="background:#f8f8f8;padding:16px 24px;border-radius:6px;border:1px solid #eee;">
            <b>拦截时服务器返回的HTTP响应头：</b><br><br>
            <code>
                HTTP/1.1 403 Forbidden<br>
                Content-Type: text/plain; charset=utf-8<br>
            </code>
            <br>
            <b>响应体：</b> <code>Bad UserAgent</code>、<code>Bad Request</code>、<code>CC Blocked</code> 等具体拦截原因（不同防护项会有所不同）
            <br><br>
            <span style="color:#888;">说明：所有被拦截的请求均返回 <code>403 Forbidden</code> 或 <code>400 Bad Request</code> 状态码，并带有简明文本描述，不返回页面源码。</span>
        </div>
    </div>
    <?php
}