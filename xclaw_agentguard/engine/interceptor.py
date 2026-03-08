"""
XClaw AgentGuard - LLM Interceptor (Optional)

Optional middleware for automatic LLM call interception.
Requires the engine to be running.

Usage:
    # Framework mode (always works, no engine needed)
    from xclaw_agentguard import PromptInjectionDetector
    
    # Engine + Interceptor mode (optional enhancement)
    from xclaw_agentguard.engine.interceptor import protect_openai
    protect_openai()  # Auto-protect OpenAI calls
"""

import os
import json
import socket
from typing import Optional, Dict, Any, Callable
from functools import wraps
import logging

logger = logging.getLogger('agentguard-interceptor')


class LLMInterceptor:
    """Optional LLM call interceptor - requires engine"""
    
    def __init__(self, engine_socket: str = "/tmp/xclaw_agentguard.sock"):
        self.engine_socket = engine_socket
        self._original_openai = None
        self._patched = False
    
    def _send_to_engine(self, action: str, data: Dict) -> Optional[Dict]:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(self.engine_socket)
            sock.send(json.dumps({'action': action, **data}).encode())
            response = sock.recv(65536).decode()
            sock.close()
            return json.loads(response)
        except Exception as e:
            logger.error(f"Engine communication failed: {e}")
            return None
    
    def scan_prompt(self, content: str) -> Dict[str, Any]:
        result = self._send_to_engine('scan', {'content': content})
        if result and result.get('status') == 'ok':
            return result.get('result', {'detected': False})
        return {'detected': False, 'error': 'Scan failed'}
    
    def is_threat(self, scan_result: Dict) -> bool:
        return scan_result.get('detected', False) and \
               scan_result.get('threat_level') in ['HIGH', 'CRITICAL']
    
    def patch_openai(self):
        """Monkey-patch OpenAI library"""
        if self._patched:
            return
        
        try:
            import openai
            self._original_openai = openai.chat.completions.create
            
            @wraps(self._original_openai)
            def protected_create(*args, **kwargs):
                messages = kwargs.get('messages', [])
                prompt_text = self._extract_from_messages(messages)
                
                if prompt_text:
                    result = self.scan_prompt(prompt_text)
                    if self.is_threat(result):
                        raise SecurityException(f"Threat: {result.get('threat_level')}")
                
                return self._original_openai(*args, **kwargs)
            
            openai.chat.completions.create = protected_create
            self._patched = True
            logger.info("OpenAI patched")
        except ImportError:
            logger.warning("OpenAI not installed")
    
    def unpatch_openai(self):
        if self._patched and self._original_openai:
            try:
                import openai
                openai.chat.completions.create = self._original_openai
                self._patched = False
            except ImportError:
                pass
    
    @staticmethod
    def _extract_from_messages(messages) -> str:
        texts = []
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get('content', '')
                if isinstance(content, str):
                    texts.append(content)
        return "\n".join(texts)


class SecurityException(Exception):
    """Security threat detected"""
    pass


def protect_openai():
    """Enable OpenAI protection"""
    interceptor = LLMInterceptor()
    interceptor.patch_openai()
    return interceptor


def scan_prompt(content: str) -> Dict[str, Any]:
    interceptor = LLMInterceptor()
    return interceptor.scan_prompt(content)