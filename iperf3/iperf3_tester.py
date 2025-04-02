import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import json
import time
import socket
import re
import subprocess
from typing import Dict, List, Tuple
import os
from datetime import datetime

class Iperf3Tester:
    def __init__(self, root):
        self.root = root
        self.root.title("iperf3 性能测试工具")
        self.root.geometry("1200x900")
        
        # 存储测试结果
        self.test_results = {}
        self.active_tests = {}
        self.stop_flag = False
        self.max_concurrent_tests = 5  # 最大并发测试数
        
        # 检查iperf3是否已安装
        self.check_iperf3_installation()
        
        self.create_widgets()
        
    def check_iperf3_installation(self):
        try:
            # 检查iperf3是否在系统PATH中
            result = subprocess.run(['iperf3', '--version'], capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception("iperf3命令执行失败")
            print("iperf3检查成功")
        except Exception as e:
            print(f"iperf3检查失败: {str(e)}")
            messagebox.showerror("错误", 
                "未找到iperf3。\n"
                "请按照以下步骤安装iperf3：\n\n"
                "Windows:\n"
                "1. 下载iperf3: https://iperf.fr/iperf-download.php\n"
                "2. 解压并添加到系统PATH\n"
                "3. 确保iperf3.exe在PATH中\n\n"
                "Linux:\n"
                "sudo apt-get install iperf3  # Ubuntu/Debian\n"
                "sudo yum install iperf3      # CentOS/RHEL\n\n"
                "macOS:\n"
                "brew install iperf3")
            self.root.quit()

    def validate_ip(self, ip: str) -> bool:
        # 检查是否包含端口号
        if ':' in ip:
            ip_part, port_part = ip.split(':')
            try:
                port = int(port_part)
                if not (1 <= port <= 65535):
                    return False
            except ValueError:
                return False
            ip = ip_part
        
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        return all(0 <= int(part) <= 255 for part in ip.split('.'))

    def check_duplicate_ips(self, ips: List[str]) -> Tuple[bool, str]:
        # 创建一个字典来存储IP:端口组合及其出现次数
        ip_count = {}
        for ip in ips:
            ip_count[ip] = ip_count.get(ip, 0) + 1
        
        # 找出所有重复的IP
        duplicate_ips = [ip for ip, count in ip_count.items() if count > 1]
        if duplicate_ips:
            return False, f"IP:端口重复: {', '.join(duplicate_ips)}"
        return True, ""

    def validate_ips(self, ips: List[str]) -> Tuple[bool, str]:
        # 首先检查是否有重复的IP:端口组合
        is_unique, error_msg = self.check_duplicate_ips(ips)
        if not is_unique:
            return False, error_msg
            
        # 然后检查IP地址格式
        invalid_ips = [ip for ip in ips if not self.validate_ip(ip.strip())]
        if invalid_ips:
            return False, f"无效的IP地址或端口: {', '.join(invalid_ips)}"
        return True, ""

    def create_widgets(self):
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建输入区域
        input_frame = ttk.LabelFrame(main_frame, text="测试配置", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        
        # 配置grid权重，使第二列（输入框）可以扩展
        input_frame.grid_columnconfigure(1, weight=1)
        
        # 客户端 IP 输入
        ttk.Label(input_frame, text="客户端 IP (空格分隔):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.client_ip_text = scrolledtext.ScrolledText(input_frame, height=5)
        self.client_ip_text.grid(row=0, column=1, sticky=tk.EW, pady=5)
        self.client_ip_text.insert(tk.END, self.get_local_ip())
        self.client_ip_text.bind('<KeyRelease>', self.validate_ip_count)
        
        # 服务端 IP 输入
        ttk.Label(input_frame, text="服务端 IP (空格分隔):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.server_ip_text = scrolledtext.ScrolledText(input_frame, height=5)
        self.server_ip_text.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.server_ip_text.bind('<KeyRelease>', self.validate_ip_count)
        
        # 添加IP数量提示标签
        self.ip_count_label = ttk.Label(input_frame, text="", foreground="red")
        self.ip_count_label.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        # 测试持续时间
        ttk.Label(input_frame, text="测试持续时间 (秒):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.duration_entry = ttk.Entry(input_frame, width=10)
        self.duration_entry.grid(row=3, column=1, sticky=tk.W, pady=5)
        self.duration_entry.insert(0, "10")
        
        # 测试协议选择
        ttk.Label(input_frame, text="测试协议:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.protocol_var = tk.StringVar(value="TCP")
        protocol_frame = ttk.Frame(input_frame)
        protocol_frame.grid(row=4, column=1, sticky=tk.W, pady=5)
        ttk.Radiobutton(protocol_frame, text="TCP", variable=self.protocol_var, value="TCP").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(protocol_frame, text="UDP", variable=self.protocol_var, value="UDP").pack(side=tk.LEFT, padx=5)
        
        # 按钮区域
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="开始测试", command=self.start_test)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="停止测试", command=self.stop_test, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="清除结果", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # 添加保存结果按钮
        self.save_button = ttk.Button(button_frame, text="保存结果", command=self.save_results)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        # 创建结果显示区域
        results_frame = ttk.LabelFrame(main_frame, text="测试结果", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 创建表格显示结果
        self.tree = ttk.Treeview(results_frame, columns=("client", "server", "protocol", "transfer", "bitrate", "retransmits", "status"), show="headings", height=10)
        self.tree.heading("client", text="客户端 IP")
        self.tree.heading("server", text="服务端 IP")
        self.tree.heading("protocol", text="协议")
        self.tree.heading("transfer", text="传输量")
        self.tree.heading("bitrate", text="比特率")
        self.tree.heading("retransmits", text="重传次数")
        self.tree.heading("status", text="状态")
        
        # 设置列宽和对齐方式
        self.tree.column("client", width=120, anchor="center")
        self.tree.column("server", width=120, anchor="center")
        self.tree.column("protocol", width=60, anchor="center")
        self.tree.column("transfer", width=100, anchor="center")
        self.tree.column("bitrate", width=100, anchor="center")
        self.tree.column("retransmits", width=80, anchor="center")
        self.tree.column("status", width=100, anchor="center")
        
        # 设置表头对齐方式
        for col in ("client", "server", "protocol", "transfer", "bitrate", "retransmits", "status"):
            self.tree.heading(col, text=self.tree.heading(col)["text"], anchor="center")
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 日志区域
        log_frame = ttk.LabelFrame(main_frame, text="日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 增加日志区域高度并添加自动滚动
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 设置日志文本的字体和颜色
        self.log_text.configure(font=('Courier New', 10))
        self.log_text.tag_configure('error', foreground='red')
        self.log_text.tag_configure('success', foreground='green')
        self.log_text.tag_configure('info', foreground='blue')
        
        # 添加日志控制按钮
        log_control_frame = ttk.Frame(log_frame)
        log_control_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(log_control_frame, text="清除日志", command=lambda: self.log_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_control_frame, text="滚动到底部", command=lambda: self.log_text.see(tk.END)).pack(side=tk.LEFT, padx=5)
        
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def log(self, message):
        timestamp = time.strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"{timestamp} - {message}\n")
        
        # 根据消息类型设置不同的颜色
        if "错误" in message or "失败" in message:
            self.log_text.tag_add('error', f"{self.log_text.index('end-2c linestart')}", "end-1c")
        elif "完成" in message or "成功" in message:
            self.log_text.tag_add('success', f"{self.log_text.index('end-2c linestart')}", "end-1c")
        else:
            self.log_text.tag_add('info', f"{self.log_text.index('end-2c linestart')}", "end-1c")
        
        # 自动滚动到底部
        self.log_text.see(tk.END)
    
    def validate_ip_count(self, event=None):
        # 获取客户端和服务端IP列表（使用空格分隔）
        client_ips = [ip.strip() for ip in self.client_ip_text.get("1.0", tk.END).split() if ip.strip()]
        server_ips = [ip.strip() for ip in self.server_ip_text.get("1.0", tk.END).split() if ip.strip()]
        
        # 首先检查是否有重复的IP:端口组合
        client_unique, client_duplicate_error = self.check_duplicate_ips(client_ips)
        server_unique, server_duplicate_error = self.check_duplicate_ips(server_ips)
        
        if not client_unique or not server_unique:
            error_msg = ""
            if not client_unique:
                error_msg += f"客户端{client_duplicate_error}\n"
            if not server_unique:
                error_msg += f"服务端{server_duplicate_error}"
            self.ip_count_label.config(
                text=error_msg,
                foreground="red"
            )
            return
            
        # 然后检查IP地址格式
        client_valid, client_error = self.validate_ips(client_ips)
        server_valid, server_error = self.validate_ips(server_ips)
        
        # 检查IP数量
        if not client_valid or not server_valid:
            self.ip_count_label.config(
                text=f"IP格式错误: {client_error} {server_error}",
                foreground="red"
            )
            return
        
        if len(client_ips) != len(server_ips):
            self.ip_count_label.config(
                text=f"IP数量不匹配: 客户端 {len(client_ips)} 个, 服务端 {len(server_ips)} 个",
                foreground="red"
            )
        else:
            self.ip_count_label.config(
                text=f"IP数量匹配: {len(client_ips)} 对",
                foreground="green"
            )
    
    def start_test(self):
        # 获取输入值（使用空格分隔）
        client_ips = [ip.strip() for ip in self.client_ip_text.get("1.0", tk.END).split() if ip.strip()]
        server_ips = [ip.strip() for ip in self.server_ip_text.get("1.0", tk.END).split() if ip.strip()]
        
        # 验证IP地址
        is_valid, error_msg = self.validate_ips(client_ips + server_ips)
        if not is_valid:
            messagebox.showerror("错误", error_msg)
            return
        
        if not client_ips:
            messagebox.showerror("错误", "请输入至少一个客户端 IP")
            return
        
        if not server_ips:
            messagebox.showerror("错误", "请输入至少一个服务端 IP")
            return
        
        # 检查客户端和服务端IP数量是否匹配
        if len(client_ips) != len(server_ips):
            messagebox.showerror("错误", f"客户端和服务端IP数量必须相同\n客户端: {len(client_ips)} 个\n服务端: {len(server_ips)} 个")
            return
        
        try:
            duration = int(self.duration_entry.get())
            if duration <= 0:
                raise ValueError("持续时间必须大于 0")
        except ValueError as e:
            messagebox.showerror("错误", f"无效的持续时间: {str(e)}")
            return
        
        protocol = self.protocol_var.get()
        
        # 更新按钮状态
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # 清除之前的结果
        self.clear_results()
        
        # 重置停止标志
        self.stop_flag = False
        
        # 启动测试线程
        self.test_thread = threading.Thread(
            target=self.run_tests,
            args=(client_ips, server_ips, duration, protocol)
        )
        self.test_thread.daemon = True
        self.test_thread.start()
    
    def run_tests(self, client_ips, server_ips, duration, protocol):
        self.log(f"开始测试: {len(client_ips)} 对客户端-服务端")
        
        try:
            # 为每对客户端-服务端创建一个测试
            active_test_count = 0
            for client_ip, server_ip in zip(client_ips, server_ips):
                if self.stop_flag:
                    break
                
                # 等待，直到当前运行的测试数量小于最大并发数
                while active_test_count >= self.max_concurrent_tests:
                    if self.stop_flag:
                        break
                    time.sleep(0.5)
                    active_test_count = sum(1 for test in self.active_tests.values() if test["thread"].is_alive())
                
                if self.stop_flag:
                    break
                
                test_id = f"{client_ip}-{server_ip}"
                self.log(f"启动测试: 客户端 {client_ip} -> 服务端 {server_ip}")
                
                # 在表格中添加一行
                item_id = self.tree.insert("", tk.END, values=(
                    client_ip, server_ip, protocol, "等待中...", "等待中...", "等待中...", "进行中"
                ))
                
                # 启动测试线程
                test_thread = threading.Thread(
                    target=self.run_single_test,
                    args=(client_ip, server_ip, duration, protocol, item_id)
                )
                test_thread.daemon = True
                test_thread.start()
                
                self.active_tests[test_id] = {
                    "thread": test_thread,
                    "item_id": item_id
                }
                active_test_count += 1
                
                # 稍微延迟以避免同时启动太多测试
                time.sleep(0.5)
            
            # 等待所有测试完成
            while any(test["thread"].is_alive() for test in self.active_tests.values()):
                if self.stop_flag:
                    self.log("测试被用户中止")
                    break
                time.sleep(0.5)
        finally:
            # 恢复按钮状态
            self.root.after(0, lambda: self.start_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
            
            if not self.stop_flag:
                self.log("所有测试完成")
    
    def run_single_test(self, client_ip, server_ip, duration, protocol, item_id):
        try:
            # 解析服务器IP和端口
            server_parts = server_ip.split(':')
            server_ip = server_parts[0]
            server_port = server_parts[1] if len(server_parts) > 1 else "5201"  # 默认端口5201
            
            # 构建iperf3命令
            cmd = [
                'iperf3',
                '-c', server_ip,
                '-p', server_port,  # 添加端口参数
                '-t', str(duration)
            ]
            
            if protocol == "UDP":
                cmd.extend(['-u'])  # UDP模式
            
            # 将命令转换为字符串
            cmd_str = ' '.join(cmd)
            self.log(f"执行命令: {cmd_str}")
            
            # 使用subprocess.Popen来实时获取输出
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # 存储所有输出行
            output_lines = []
            
            # 实时读取输出
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    line = output.strip()
                    output_lines.append(line)
                    self.log(f"实时输出: {line}")
            
            # 获取错误输出
            stderr = process.stderr.read()
            if stderr:
                self.log(f"错误输出: {stderr.strip()}")
            
            # 获取最终输出
            stdout, _ = process.communicate()
            if stdout:
                self.log(f"最终输出: {stdout.strip()}")
            
            if process.returncode != 0:
                error_msg = stderr.strip() or "未知错误"
                self.log(f"命令执行失败: {error_msg}")
                self.root.after(0, lambda: self.tree.item(item_id, values=(
                    client_ip, server_ip + (f":{server_port}" if server_port != "5201" else ""), protocol, "N/A", "N/A", "N/A", f"错误: {error_msg}"
                )))
                self.log(f"测试失败: {client_ip} -> {server_ip}: {error_msg}")
            else:
                try:
                    # 解析输出结果
                    # 查找包含测试数据的行
                    test_data_lines = []
                    for line in output_lines:
                        if '[ ID]' in line and 'Interval' in line:
                            test_data_lines.append(line)
                        elif 'sender' in line.lower() and 'receiver' in line.lower():
                            test_data_lines.append(line)
                    
                    if test_data_lines:
                        # 获取最后一行测试数据
                        last_line = test_data_lines[-1]
                        # 解析数据
                        parts = last_line.split()
                        
                        # 查找传输量和比特率
                        transfer = "N/A"
                        bitrate = "N/A"
                        retransmits = "N/A"
                        
                        # 遍历所有行查找数据
                        for line in output_lines:
                            # 查找传输量
                            if 'MBytes' in line or 'KBytes' in line:
                                transfer_match = re.search(r'(\d+\.?\d*)\s*(MBytes|KBytes)', line)
                                if transfer_match:
                                    transfer = f"{transfer_match.group(1)} {transfer_match.group(2)}"
                            
                            # 查找比特率
                            if 'Mbits/sec' in line or 'Kbits/sec' in line:
                                bitrate_match = re.search(r'(\d+\.?\d*)\s*(Mbits/sec|Kbits/sec)', line)
                                if bitrate_match:
                                    bitrate = f"{bitrate_match.group(1)} {bitrate_match.group(2)}"
                            
                            # 查找重传次数
                            if "retransmits" in line:
                                retransmits_match = re.search(r'(\d+)\s*retransmits', line)
                                if retransmits_match:
                                    retransmits = retransmits_match.group(1)
                        
                        # 格式化数值，确保对齐
                        transfer = transfer if transfer != "N/A" else "N/A"
                        bitrate = bitrate if bitrate != "N/A" else "N/A"
                        retransmits = retransmits if retransmits != "N/A" else "N/A"
                        
                        self.log(f"解析结果: 传输={transfer}, 比特率={bitrate}, 重传={retransmits}")
                        
                        self.root.after(0, lambda: self.tree.item(item_id, values=(
                            client_ip, server_ip + (f":{server_port}" if server_port != "5201" else ""), protocol, transfer, bitrate, retransmits, "完成"
                        )))
                        
                        self.log(f"测试完成: {client_ip} -> {server_ip}: {bitrate}")
                    else:
                        raise Exception("未找到测试数据行")
                except Exception as e:
                    self.log(f"结果解析错误: {str(e)}")
                    raise Exception(f"无法解析测试结果: {str(e)}")
        except Exception as e:
            error_msg = str(e)
            if "Connection refused" in error_msg:
                error_msg = "连接被拒绝，请确保服务端正在运行"
            elif "No route to host" in error_msg:
                error_msg = "无法连接到主机，请检查网络连接"
            elif "Permission denied" in error_msg:
                error_msg = "权限被拒绝，请检查防火墙设置"
            
            self.root.after(0, lambda: self.tree.item(item_id, values=(
                client_ip, server_ip + (f":{server_port}" if server_port != "5201" else ""), protocol, "N/A", "N/A", "N/A", f"错误: {error_msg}"
            )))
            self.log(f"测试异常: {client_ip} -> {server_ip}: {error_msg}")
    
    def stop_test(self):
        self.stop_flag = True
        self.log("正在停止测试...")
        
        # 更新所有进行中的测试状态
        for test_info in self.active_tests.values():
            item_id = test_info["item_id"]
            current_values = self.tree.item(item_id, "values")
            if current_values[6] == "进行中":
                self.tree.item(item_id, values=(
                    current_values[0], current_values[1], current_values[2],
                    "已中止", "已中止", "已中止", "已中止"
                ))
    
    def clear_results(self):
        # 清除表格
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 清除结果存储
        self.test_results = {}
        self.active_tests = {}
        
        # 清除日志
        self.log_text.delete(1.0, tk.END)
        self.log("结果已清除")

    def save_results(self):
        # 获取所有测试结果
        results = []
        for item in self.tree.get_children():
            values = self.tree.item(item)["values"]
            results.append({
                "client_ip": values[0],
                "server_ip": values[1],
                "protocol": values[2],
                "transfer": values[3],
                "bitrate": values[4],
                "retransmits": values[5],
                "status": values[6],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        
        if not results:
            messagebox.showwarning("警告", "没有可保存的测试结果")
            return
        
        # 选择保存路径
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"iperf3_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)
                self.log(f"测试结果已保存到: {filename}")
                messagebox.showinfo("成功", "测试结果已保存")
            except Exception as e:
                self.log(f"保存结果失败: {str(e)}")
                messagebox.showerror("错误", f"保存结果失败: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = Iperf3Tester(root)
    root.mainloop() 