import asyncio
import discord
from discord.ext import commands
import g4f
import subprocess
import json
import re
from datetime import datetime
from typing import List, Dict, Optional
import flet as ft
import threading
import queue
import hashlib
import pickle

CONFIG_PATH = 'config.pkl'
DEFAULT_CONFIG = {
    "discord_token": "",
    "command_prefix": "!",
    "os_type": "windows",  # windows или linux
    "g4f_model": g4f.models.gpt_4,  # Модель G4F
    "message_history_limit": 50,
    "dangerous_commands": [
        "rm -rf", "del /f", "format", "fdisk", "mkfs", "dd if=", 
        "shutdown", "reboot", "halt", "poweroff", "taskkill /f",
        "reg delete", "netsh", "iptables", "chmod 777", "chown",
        "wget", "curl", "powershell", "cmd", "bash", "sh"
    ],
    "auto_approve_safe": False,
    "max_command_length": 1000
}

class SecurityChecker:
    def __init__(self, dangerous_commands: List[str]):
        self.dangerous_commands = dangerous_commands
        self.suspicious_patterns = [
            r'[\|&;]',  # Pipe и chain операторы
            r'>\s*[/\\]',  # Redirection в системные папки
            r'<.*>',  # Потенциальные redirection
            r'\$\([^)]*\)',  # Command substitution
            r'`[^`]*`',  # Backtick execution
        ]
    
    def check_command(self, command: str) -> Dict:
        """Проверяет команду на безопасность"""
        result = {
            "safe": True,
            "warnings": [],
            "dangerous_parts": [],
            "risk_level": "low"
        }
        
        command_lower = command.lower()
        
        # Проверка на опасные команды
        for dangerous_cmd in self.dangerous_commands:
            if dangerous_cmd.lower() in command_lower:
                result["safe"] = False
                result["dangerous_parts"].append(dangerous_cmd)
                result["warnings"].append(f"Обнаружена опасная команда: {dangerous_cmd}")
        
        # Проверка на подозрительные паттерны
        for pattern in self.suspicious_patterns:
            if re.search(pattern, command):
                result["safe"] = False
                result["warnings"].append(f"Подозрительный паттерн: {pattern}")
        
        # Определение уровня риска
        if len(result["dangerous_parts"]) > 2:
            result["risk_level"] = "high"
        elif len(result["dangerous_parts"]) > 0:
            result["risk_level"] = "medium"
        
        return result

class MessageHistory:
    def __init__(self, limit: int = 50):
        self.limit = limit
        self.messages = []
    
    def add_message(self, role: str, content: str):
        """Добавляет сообщение в историю"""
        self.messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat()
        })
        
        if len(self.messages) > self.limit:
            self._compress_history()
    
    def _compress_history(self):
        """Сжимает историю, сохраняя важные сообщения"""
        # Оставляем последние 20 сообщений и каждое 5-е из старых
        if len(self.messages) > self.limit:
            recent = self.messages[-20:]
            old_compressed = self.messages[:-20:5]  # Каждое 5-е сообщение
            self.messages = old_compressed + recent
    
    def get_history(self) -> List[Dict]:
        """Возвращает историю сообщений"""
        return self.messages
    
    def clear(self):
        """Очищает историю"""
        self.messages = []

class CommandExecutor:
    def __init__(self, os_type: str = "windows"):
        self.os_type = os_type
    
    def execute_command(self, command: str) -> Dict:
        """Выполняет команду и возвращает результат"""
        try:
            if self.os_type == "windows":
                result = subprocess.run(
                    command, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
            else:  # linux
                result = subprocess.run(
                    command, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
            
            return {
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Команда превысила лимит времени выполнения (30 сек)"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

class DiscordBot:
    def __init__(self, config: Dict):
        self.config = config
        self.history = MessageHistory(config.get("message_history_limit", 50))
        self.security_checker = SecurityChecker(config.get("dangerous_commands", []))
        self.executor = CommandExecutor(config.get("os_type", "windows"))
        self.pending_commands = {}  # Для хранения команд, ожидающих подтверждения
        
        intents = discord.Intents.default()
        intents.message_content = True
        intents.dm_messages = True
        
        self.bot = commands.Bot(
            command_prefix=config.get("command_prefix", "!"),
            intents=intents
        )
        
        self.setup_commands()
    
    def setup_commands(self):
        @self.bot.event
        async def on_ready():
            print(f'{self.bot.user} подключен к Discord!')
        
        @self.bot.command(name='ask')
        async def ask_ai(ctx, *, question: str):
            """Задать вопрос AI"""
            await ctx.send("🤔 Обрабатываю запрос...")
            
            try:
                # Добавляем сообщение в историю
                self.history.add_message("user", question)
                
                # Получаем контекст истории
                history_context = self._build_context()
                
                # Запрос к G4F
                response = await g4f.ChatCompletion.create_async(
                    model=self.config.get("g4f_model", g4f.models.gpt_4),
                    messages=[
                        {"role": "system", "content": f"Ты помощник для выполнения команд в {self.config['os_type']}. Когда нужно выполнить команду, напиши её в формате: COMMAND: <команда>"},
                        {"role": "system", "content": f"История: {history_context}"},
                        {"role": "user", "content": question}
                    ]
                )
                
                self.history.add_message("assistant", response)
                
                # Проверяем, есть ли команда в ответе
                if "COMMAND:" in response:
                    await self._handle_command_response(ctx, response)
                else:
                    await ctx.send(f"🤖 **Ответ AI:**\n{response}")
                    
            except Exception as e:
                await ctx.send(f"❌ Ошибка при обращении к AI: {str(e)}")
        
        @self.bot.command(name='exec')
        async def execute_command(ctx, *, command: str):
            """Выполнить команду напрямую"""
            await self._execute_with_security_check(ctx, command)
        
        @self.bot.command(name='approve')
        async def approve_command(ctx, command_id: str = None):
            """Подтвердить выполнение команды"""
            if command_id and command_id in self.pending_commands:
                command = self.pending_commands.pop(command_id)
                await self._execute_command_directly(ctx, command)
            else:
                await ctx.send("❌ Команда не найдена или уже выполнена")
        
        @self.bot.command(name='history')
        async def show_history(ctx):
            """Показать историю сообщений"""
            history = self.history.get_history()
            if not history:
                await ctx.send("📝 История сообщений пуста")
                return
            
            history_text = "📝 **История сообщений:**\n"
            for msg in history[-10:]:  # Показываем последние 10
                role_icon = "👤" if msg["role"] == "user" else "🤖"
                content = msg["content"][:100] + "..." if len(msg["content"]) > 100 else msg["content"]
                history_text += f"{role_icon} {content}\n"
            
            await ctx.send(history_text)
        
        @self.bot.command(name='clear')
        async def clear_history(ctx):
            """Очистить историю"""
            self.history.clear()
            await ctx.send("🗑️ История сообщений очищена")
    
    async def _handle_command_response(self, ctx, response: str):
        """Обрабатывает ответ AI с командой"""
        lines = response.split('\n')
        commands = []
        text_parts = []
        
        for line in lines:
            if line.strip().startswith('COMMAND:'):
                command = line.replace('COMMAND:', '').strip()
                commands.append(command)
            else:
                text_parts.append(line)
        
        # Отправляем текстовую часть ответа
        if text_parts:
            text_response = '\n'.join(text_parts).strip()
            if text_response:
                await ctx.send(f"🤖 **Ответ AI:**\n{text_response}")
        
        # Обрабатываем команды
        for command in commands:
            await self._execute_with_security_check(ctx, command)
    
    async def _execute_with_security_check(self, ctx, command: str):
        """Выполняет команду с проверкой безопасности"""
        if len(command) > self.config.get("max_command_length", 1000):
            await ctx.send("❌ Команда слишком длинная")
            return
        
        # Проверка безопасности
        security_result = self.security_checker.check_command(command)
        
        if security_result["safe"] or self.config.get("auto_approve_safe", False):
            await self._execute_command_directly(ctx, command)
        else:
            await self._request_approval(ctx, command, security_result)
    
    async def _request_approval(self, ctx, command: str, security_result: Dict):
        """Запрашивает подтверждение для выполнения опасной команды"""
        command_id = hashlib.md5(command.encode()).hexdigest()[:8]
        self.pending_commands[command_id] = command
        
        risk_colors = {"low": "🟢", "medium": "🟡", "high": "🔴"}
        risk_color = risk_colors.get(security_result["risk_level"], "🟡")
        
        warning_text = f"{risk_color} **ВНИМАНИЕ! Потенциально опасная команда**\n"
        warning_text += f"📋 **Команда:** `{command}`\n"
        warning_text += f"⚠️ **Уровень риска:** {security_result['risk_level']}\n"
        
        if security_result["warnings"]:
            warning_text += "🚨 **Предупреждения:**\n"
            for warning in security_result["warnings"]:
                warning_text += f"• {warning}\n"
        
        warning_text += f"\n🔧 Для выполнения используйте: `!approve {command_id}`"
        
        await ctx.send(warning_text)
    
    async def _execute_command_directly(self, ctx, command: str):
        """Выполняет команду напрямую"""
        await ctx.send(f"⚙️ Выполняю команду: `{command}`")
        
        result = self.executor.execute_command(command)
        
        if result["success"]:
            output = ""
            if result["stdout"]:
                output += f"📤 **Вывод:**\n```\n{result['stdout']}\n```\n"
            if result["stderr"]:
                output += f"⚠️ **Предупреждения:**\n```\n{result['stderr']}\n```\n"
            if result["returncode"] != 0:
                output += f"🔴 **Код возврата:** {result['returncode']}\n"
            
            if not output:
                output = "✅ Команда выполнена успешно"
            
            # Ограничиваем длину вывода
            if len(output) > 1800:
                output = output[:1800] + "\n... (вывод обрезан)"
            
            await ctx.send(output)
        else:
            await ctx.send(f"❌ **Ошибка выполнения:**\n```\n{result['error']}\n```")
    
    def _build_context(self) -> str:
        """Строит контекст из истории сообщений"""
        history = self.history.get_history()
        if not history:
            return ""
        
        context = ""
        for msg in history[-5:]:  # Берем последние 5 сообщений
            role = "Пользователь" if msg["role"] == "user" else "AI"
            content = msg["content"][:200] + "..." if len(msg["content"]) > 200 else msg["content"]
            context += f"{role}: {content}\n"
        
        return context
    
    def run(self):
        """Запускает бота"""
        token = self.config.get("discord_token")
        if not token:
            raise ValueError("Discord токен не указан")
        
        self.bot.run(token)

class BotGUI:
    def __init__(self):
        self.config = self._load_config()
        self.bot_instance = None
        self.bot_thread = None
        self.command_queue = queue.Queue()

    def _load_config(self) -> Dict:
        """Загружает конфигурацию"""
        try:
            with open(CONFIG_PATH, 'rb') as f:
                config = pickle.load(f)
                # Объединяем с дефолтными значениями
                for key, value in DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
                return config
        except FileNotFoundError:
            return DEFAULT_CONFIG.copy()

    def _save_config(self):
        """Сохраняет конфигурацию"""
        with open(CONFIG_PATH, 'wb') as f:
            pickle.dump(self.config, f)
    
    def main(self, page: ft.Page):
        page.title = "Discord Commander Bot"
        page.theme_mode = ft.ThemeMode.LIGHT
        page.window_width = 900
        page.window_height = 1000
        
        # Статус бота
        self.status_text = ft.Text("🔴 Бот остановлен", color=ft.colors.RED)
        
        # Основные настройки
        self.token_field = ft.TextField(
            label="Discord Bot Token",
            value=self.config.get("discord_token", ""),
            password=True,
            width=400
        )
        
        self.prefix_field = ft.TextField(
            label="Префикс команд",
            value=self.config.get("command_prefix", "!"),
            width=100
        )
        
        self.os_dropdown = ft.Dropdown(
            label="Операционная система",
            value=self.config.get("os_type", "windows"),
            options=[
                ft.dropdown.Option("windows", "Windows"),
                ft.dropdown.Option("linux", "Linux")
            ],
            width=200
        )
        
        self.provider_dropdown = ft.Dropdown(
            label="G4F Provider",
            value=self.config.get("g4f_model", g4f.models.gpt_4),
            options=[
                ft.dropdown.Option(g4f.models.gpt_4, g4f.models.gpt_4.name),
                ft.dropdown.Option(g4f.models.gpt_4_1_mini, g4f.models.gpt_4_1_mini.name),
                ft.dropdown.Option(g4f.models.llama_2_70b, g4f.models.llama_2_70b.name),
                ft.dropdown.Option(g4f.models.llama_3_1_405b, g4f.models.llama_3_1_405b.name),
            ],
            width=200
        )
        
        self.history_limit_field = ft.TextField(
            label="Лимит истории",
            value=str(self.config.get("message_history_limit", 50)),
            width=150
        )
        
        self.auto_approve_checkbox = ft.Checkbox(
            label="Автоматически выполнять безопасные команды",
            value=self.config.get("auto_approve_safe", False)
        )
        
        # Список опасных команд
        self.dangerous_commands_field = ft.TextField(
            label="Опасные команды (через запятую)",
            value=", ".join(self.config.get("dangerous_commands", [])),
            multiline=True,
            min_lines=3,
            max_lines=5,
            width=500
        )
        
        # Кнопки управления
        self.start_button = ft.ElevatedButton(
            "Запустить бота",
            icon=ft.icons.PLAY_ARROW,
            on_click=self.start_bot,
            bgcolor=ft.colors.GREEN
        )
        
        self.stop_button = ft.ElevatedButton(
            "Остановить бота",
            icon=ft.icons.STOP,
            on_click=self.stop_bot,
            bgcolor=ft.colors.RED,
            disabled=True
        )
        
        self.save_button = ft.ElevatedButton(
            "Сохранить настройки",
            icon=ft.icons.SAVE,
            on_click=self.save_settings
        )
        
        # Лог
        self.log_text = ft.TextField(
            label="Лог бота",
            multiline=True,
            min_lines=10,
            max_lines=10,
            width=800,
            read_only=True
        )
        
        # Компоновка интерфейса
        page.add(
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Text("Discord Commander Bot", size=24, weight=ft.FontWeight.BOLD),
                        self.status_text
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    
                    ft.Divider(),
                    
                    ft.Text("Основные настройки", size=18, weight=ft.FontWeight.BOLD),
                    ft.Row([self.token_field]),
                    ft.Row([self.prefix_field, self.os_dropdown, self.provider_dropdown]),
                    ft.Row([self.history_limit_field, self.auto_approve_checkbox]),
                    
                    ft.Divider(),
                    
                    ft.Text("Безопасность", size=18, weight=ft.FontWeight.BOLD),
                    ft.Row([self.dangerous_commands_field]),
                    
                    ft.Divider(),
                    
                    ft.Text("Управление", size=18, weight=ft.FontWeight.BOLD),
                    ft.Row([self.start_button, self.stop_button, self.save_button]),
                    
                    ft.Divider(),
                    
                    ft.Text("Лог", size=18, weight=ft.FontWeight.BOLD),
                    self.log_text
                ], spacing=10),
                padding=20
            )
        )
    
    def start_bot(self, e):
        """Запускает бота"""
        try:
            # Сохраняем настройки
            self.save_settings(None)
            
            # Создаем экземпляр бота
            self.bot_instance = DiscordBot(self.config)
            
            # Запускаем в отдельном потоке
            self.bot_thread = threading.Thread(target=self._run_bot_thread)
            self.bot_thread.daemon = True
            self.bot_thread.start()
            
            # Обновляем интерфейс
            self.status_text.value = "🟢 Бот запущен"
            self.status_text.color = ft.colors.GREEN
            self.start_button.disabled = True
            self.stop_button.disabled = False
            self.log_text.value += f"[{datetime.now().strftime('%H:%M:%S')}] Бот запущен\n"
            
            self.start_button.page.update()
            
        except Exception as ex:
            self.log_text.value += f"[{datetime.now().strftime('%H:%M:%S')}] Ошибка запуска: {str(ex)}\n"
            self.start_button.page.update()
    
    def _run_bot_thread(self):
        """Запускает бота в отдельном потоке"""
        try:
            self.bot_instance.run()
        except Exception as e:
            self.log_text.value += f"[{datetime.now().strftime('%H:%M:%S')}] Ошибка бота: {str(e)}\n"
    
    def stop_bot(self, e):
        """Останавливает бота"""
        if self.bot_instance:
            try:
                asyncio.run(self.bot_instance.bot.close())
            except:
                pass
            self.bot_instance = None
        
        self.status_text.value = "🔴 Бот остановлен"
        self.status_text.color = ft.colors.RED
        self.start_button.disabled = False
        self.stop_button.disabled = True
        self.log_text.value += f"[{datetime.now().strftime('%H:%M:%S')}] Бот остановлен\n"
        
        self.stop_button.page.update()
    
    def save_settings(self, e):
        """Сохраняет настройки"""
        try:
            self.config["discord_token"] = self.token_field.value
            self.config["command_prefix"] = self.prefix_field.value
            self.config["os_type"] = self.os_dropdown.value
            self.config["g4f_model"] = self.provider_dropdown.value
            self.config["message_history_limit"] = int(self.history_limit_field.value)
            self.config["auto_approve_safe"] = self.auto_approve_checkbox.value
            
            # Обрабатываем список опасных команд
            dangerous_commands = [cmd.strip() for cmd in self.dangerous_commands_field.value.split(",")]
            self.config["dangerous_commands"] = [cmd for cmd in dangerous_commands if cmd]
            
            self._save_config()
            
            if e:  # Если вызвано кнопкой
                self.log_text.value += f"[{datetime.now().strftime('%H:%M:%S')}] Настройки сохранены\n"
                self.save_button.page.update()
                
        except Exception as ex:
            if e:
                self.log_text.value += f"[{datetime.now().strftime('%H:%M:%S')}] Ошибка сохранения: {str(ex)}\n"
                self.save_button.page.update()

def main():
    """Главная функция"""
    gui = BotGUI()
    ft.app(target=gui.main)

if __name__ == "__main__":
    main()
