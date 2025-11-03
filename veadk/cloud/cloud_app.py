# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import time
from typing import Any
from uuid import uuid4

import httpx
from a2a.client import A2ACardResolver, A2AClient
from a2a.types import (
    AgentCard,
    Message,
    MessageSendParams,
    SendMessageRequest,
    SecurityScheme,
    HTTPAuthSecurityScheme,
)
from a2a.client.middleware import ClientCallContext, ClientCallInterceptor
from a2a.client.auth import (
    AuthInterceptor,
    CredentialService,
    InMemoryContextCredentialStore,
)

from veadk.config import getenv
from veadk.utils.logger import get_logger

def handle_auth(message: str, auth_url: str):
    print(f"🔐 需要认证: {message}")
    if auth_url:
        print(f"🔗 请访问: {auth_url}")
        
logger = get_logger(__name__)


"""
A2A Client with Interactive Authentication Support

This client extends the basic A2A client functionality to handle interactive authentication flows.
When a server returns an 'auth-required' status, the client will:
1. Notify the user about the authentication requirement
2. Poll the task status until authentication is completed
3. Return the final result once authentication is done
"""

import asyncio
import logging
from typing import Any, Callable, Dict, Optional
from uuid import uuid4

import httpx
from a2a.client import A2AClient, ClientCallContext
from a2a.types import (GetTaskRequest, GetTaskSuccessResponse,
                       MessageSendParams, SendMessageRequest,
                       SendMessageSuccessResponse, Task, TaskQueryParams,
                       TaskState)

logger = logging.getLogger(__name__)

# Default polling configuration
DEFAULT_AUTH_POLLING_DELAY_SECONDS = 10
DEFAULT_AUTH_TIMEOUT_SECONDS = 300  # 5 minutes


class AuthenticationRequiredError(Exception):
    """Raised when authentication is required but no auth handler is provided."""
    
    def __init__(self, message: str, auth_url: Optional[str] = None, task_id: Optional[str] = None):
        super().__init__(message)
        self.auth_url = auth_url
        self.task_id = task_id


class AuthenticationTimeoutError(Exception):
    """Raised when authentication polling times out."""
    pass


class InteractiveAuthClient:
    """
    A2A Client with support for interactive authentication flows.
    
    This client can handle auth-required responses by polling the task status
    until authentication is completed by the user.
    """
    
    def __init__(
        self,
        a2a_client: A2AClient,
        httpx_client: Optional[httpx.AsyncClient] = None,
        auth_polling_delay: float = DEFAULT_AUTH_POLLING_DELAY_SECONDS,
        auth_timeout: float = DEFAULT_AUTH_TIMEOUT_SECONDS,
        auth_handler: Optional[Callable[[str, Optional[str]], None]] = None,
        use_agent_card: bool = False,
    ):
        """
        Initialize the interactive auth client.
        
        Args:
            a2a_client: The underlying A2A client
            httpx_client: Optional httpx client for making requests
            auth_polling_delay: Delay between polling attempts in seconds
            auth_timeout: Maximum time to wait for authentication in seconds
            auth_handler: Optional callback function to handle auth notifications
                         Signature: (message: str, auth_url: Optional[str]) -> None
            use_agent_card: Whether to use agent card for requests
        """
        self.a2a_client = a2a_client
        self.httpx_client = httpx_client
        self.auth_polling_delay = auth_polling_delay
        self.auth_timeout = auth_timeout
        self.auth_handler = auth_handler
        self.use_agent_card = use_agent_card
    
    async def send_message_with_auth(
        self,
        message: str,
        user_id: str,
        session_id: str,
        timeout: float = 60.0,
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Send a message with automatic handling of interactive authentication.

        This method wraps your original request logic and adds auth handling.

        Args:
            message: The message text to send
            user_id: User identifier
            session_id: Session identifier
            timeout: HTTP request timeout
            context: Additional context for the request

        Returns:
            The final response from the server after any required authentication

        Raises:
            AuthenticationRequiredError: If auth is required but no handler is provided
            AuthenticationTimeoutError: If authentication polling times out
        """

        # Save session_id for use in polling
        self._session_id = session_id
        
        async def request():
            send_message_payload: Dict[str, Any] = {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": message}],
                    "messageId": uuid4().hex,
                },
                "metadata": {
                    "user_id": user_id,
                    "session_id": session_id,
                },
            }
            
            try:
                message_send_request = SendMessageRequest(
                    id=uuid4().hex,
                    params=MessageSendParams(**send_message_payload),
                )

                # Use the provided context or create default context
                call_context = context or ClientCallContext(
                    state={
                        'http_kwargs': {"timeout": httpx.Timeout(timeout)},
                        'sessionId': session_id
                    }
                )

                res = await self.a2a_client.send_message(
                    message_send_request,
                    context=call_context
                )

                logger.debug(f"Message sent with response: {res}")
                
                # Check if the response indicates a task that might require auth
                if isinstance(res.root, SendMessageSuccessResponse):
                    result = res.root.result
                    
                    # If result is a Task, check for auth requirements
                    if isinstance(result, Task):
                        return await self._handle_task_response(result)
                    else:
                        # Direct response, return as-is
                        return result
                else:
                    # Handle other response types
                    return res.root.result if hasattr(res.root, 'result') else res.root
                    
            except Exception as e:
                logger.error(f"Request failed: {e}")
                return None

        return await request()
    
    async def _handle_task_response(self, task: Task) -> Any:
        """
        Handle a task response, including auth-required states.

        Args:
            task: The task returned from the server

        Returns:
            The final result after any required authentication
        """
        if task is None:
            logger.error("Received None task from server")
            return None

        if not hasattr(task, 'status') or task.status is None:
            logger.error("Task has no status")
            return task

        if not hasattr(task.status, 'state') or task.status.state is None:
            logger.error("Task status has no state")
            return task

        # Check if authentication is required
        if task.status.state == TaskState.auth_required:
            return await self._handle_auth_required(task)

        # Check if task is already completed
        elif task.status.state == TaskState.completed:
            return self._extract_task_result(task)

        # For other states (working, etc.), we could poll for completion
        # For now, return the current task
        else:
            task_id = getattr(task, 'id', 'unknown')
            logger.info(f"Task {task_id} is in state: {task.status.state}")
            return self._extract_task_result(task)
    
    async def _handle_auth_required(self, task: Task) -> Any:
        """
        Handle authentication required scenario.

        Args:
            task: The task requiring authentication

        Returns:
            The final result after authentication is completed
        """
        if task is None:
            raise Exception("Cannot handle auth for None task")

        auth_message = ""
        auth_url = None

        # Extract authentication details from the task status message
        try:
            if (hasattr(task, 'status') and task.status is not None and
                hasattr(task.status, 'message') and task.status.message is not None and
                hasattr(task.status.message, 'parts') and task.status.message.parts):

                for part in task.status.message.parts:
                    if hasattr(part, 'root') and hasattr(part.root, 'text'):
                        auth_message = part.root.text
                        # Try to extract URL from the message
                        if 'http' in auth_message:
                            # Simple URL extraction - you might want to use regex for better parsing
                            words = auth_message.split()
                            for word in words:
                                if word.startswith('http'):
                                    auth_url = word.rstrip('.,!?')
                                    break
                        break
        except Exception as e:
            logger.warning(f"Failed to extract auth message from task: {e}")
            auth_message = "Authentication required (message extraction failed)"

        # Notify about authentication requirement
        if self.auth_handler:
            self.auth_handler(auth_message, auth_url)
        else:
            # If no handler provided, raise an exception with details
            task_id = getattr(task, 'id', 'unknown') if task else 'unknown'
            raise AuthenticationRequiredError(
                f"Authentication required: {auth_message}",
                auth_url=auth_url,
                task_id=task_id
            )

        # Poll for authentication completion
        return await self._wait_for_auth_completion(task)
    
    async def _wait_for_auth_completion(self, task: Task) -> Any:
        """
        Poll the task status until authentication is completed.

        Args:
            task: The task requiring authentication

        Returns:
            The final result after authentication is completed
        """
        if task is None or not hasattr(task, 'id'):
            raise Exception("Invalid task provided for authentication polling")

        start_time = asyncio.get_event_loop().time()
        current_task = task

        while True:
            # Check timeout
            if asyncio.get_event_loop().time() - start_time > self.auth_timeout:
                raise AuthenticationTimeoutError(
                    f"Authentication timeout after {self.auth_timeout} seconds for task {task.id}"
                )

            # Check if task is now completed
            if self._is_task_complete(current_task):
                logger.info(f"Authentication completed for task {task.id}")
                return self._extract_task_result(current_task)

            # Wait before next poll
            await asyncio.sleep(self.auth_polling_delay)

            # Poll for updated task status
            try:
                current_task = await self._get_task_status(task.id)
                if current_task is None:
                    logger.warning(f"Received None task for ID {task.id}, continuing to poll...")
                    continue
            except Exception as e:
                logger.error(f"Failed to poll task status: {e}")
                # Continue polling - temporary network issues shouldn't stop the process
                continue
    
    async def _get_task_status(self, task_id: str) -> Task:
        """
        Get the current status of a task.

        Args:
            task_id: The ID of the task to check

        Returns:
            The updated task object
        """
        request = GetTaskRequest(
            id=uuid4().hex,
            params=TaskQueryParams(id=task_id),
        )

        # Create a proper context for the get_task call to avoid auth interceptor issues
        context = ClientCallContext(
            state={
                'sessionId': getattr(self, '_session_id', None),
                'http_kwargs': {"timeout": httpx.Timeout(30.0)},
            }
        )

        response = await self.a2a_client.get_task(request, context=context)

        if isinstance(response.root, GetTaskSuccessResponse):
            task = response.root.result
            if task is None:
                raise Exception(f"Task {task_id} not found or returned None")
            return task
        else:
            raise Exception(f"Failed to get task status: {response}")
    
    def _is_task_complete(self, task: Task) -> bool:
        """Check if a task is in a terminal state."""
        if task is None:
            logger.warning("Task is None, treating as incomplete")
            return False

        if not hasattr(task, 'status') or task.status is None:
            logger.warning("Task has no status, treating as incomplete")
            return False

        if not hasattr(task.status, 'state') or task.status.state is None:
            logger.warning("Task status has no state, treating as incomplete")
            return False

        terminal_states = {
            TaskState.completed,
            TaskState.failed,
            TaskState.canceled,
            TaskState.rejected,
        }

        return task.status.state in terminal_states
    
    def _extract_task_result(self, task: Task) -> Any:
        """
        Extract the result from a completed task.

        Args:
            task: The completed task

        Returns:
            The task result (artifacts or status message)
        """
        if task is None:
            logger.warning("Cannot extract result from None task")
            return None

        # If task has artifacts, return them
        if hasattr(task, 'artifacts') and task.artifacts:
            return task.artifacts

        # Otherwise return the status message
        if (hasattr(task, 'status') and task.status is not None and
            hasattr(task.status, 'message') and task.status.message is not None):
            return task.status.message

        # Fallback to the task itself
        return task


# Convenience function for simple usage
async def send_message_with_auth(
    a2a_client: A2AClient,
    message: str,
    user_id: str,
    session_id: str,
    timeout: float = 60.0,
    auth_handler: Optional[Callable[[str, Optional[str]], None]] = None,
    **kwargs
) -> Any:
    """
    Convenience function to send a message with auth handling.
    
    Args:
        a2a_client: The A2A client to use
        message: Message text to send
        user_id: User identifier
        session_id: Session identifier
        timeout: Request timeout
        auth_handler: Optional auth notification handler
        **kwargs: Additional arguments for InteractiveAuthClient
        
    Returns:
        The final response after any required authentication
    """
    client = InteractiveAuthClient(
        a2a_client=a2a_client,
        auth_handler=auth_handler,
        **kwargs
    )
    
    return await client.send_message_with_auth(
        message=message,
        user_id=user_id,
        session_id=session_id,
        timeout=timeout,
    )

class CloudApp:
    """CloudApp class.

    Args:
        name (str): The name of the cloud app.
        endpoint (str): The endpoint of the cloud app.
        use_agent_card (bool): Whether to use agent card to invoke agent. If True, the client will post to the url in agent card. Otherwise, the client will post to the endpoint directly. Default False (cause the agent card and agent usually use the same endpoint).
    """

    def __init__(
        self,
        vefaas_application_name: str = "",
        vefaas_endpoint: str = "",
        vefaas_application_id: str = "",
        use_agent_card: bool = False,
        credential_service: InMemoryContextCredentialStore = InMemoryContextCredentialStore(),
    ):
        self.vefaas_endpoint = vefaas_endpoint
        self.vefaas_application_id = vefaas_application_id
        self.vefaas_application_name = vefaas_application_name
        self.use_agent_card = use_agent_card
        self.credential_service = credential_service

        # vefaas must be set one of three
        if (
            not vefaas_endpoint
            and not vefaas_application_id
            and not vefaas_application_name
        ):
            raise ValueError(
                "VeFaaS CloudAPP must be set one of endpoint, application_id, or application_name."
            )

        if not vefaas_endpoint:
            self.vefaas_endpoint = self._get_vefaas_endpoint()

        if (
            self.vefaas_endpoint
            and not self.vefaas_endpoint.startswith("http")
            and not self.vefaas_endpoint.startswith("https")
        ):
            raise ValueError(
                f"Invalid endpoint: {vefaas_endpoint}. The endpoint must start with `http` or `https`."
            )

        if use_agent_card:
            logger.info(
                "Use agent card to invoke agent. The agent endpoint will use the `url` in agent card."
            )

        self.httpx_client = httpx.AsyncClient()

    def _get_vefaas_endpoint(
        self,
        volcengine_ak: str = getenv("VOLCENGINE_ACCESS_KEY"),
        volcengine_sk: str = getenv("VOLCENGINE_SECRET_KEY"),
    ) -> str:
        from veadk.integrations.ve_faas.ve_faas import VeFaaS

        vefaas_client = VeFaaS(access_key=volcengine_ak, secret_key=volcengine_sk)

        app = vefaas_client.get_application_details(
            app_id=self.vefaas_application_id,
            app_name=self.vefaas_application_name,
        )

        if not app:
            raise ValueError(
                f"VeFaaS CloudAPP with application_id `{self.vefaas_application_id}` or application_name `{self.vefaas_application_name}` not found."
            )

        try:
            cloud_resource = json.loads(app["CloudResource"])
            vefaas_endpoint = cloud_resource["framework"]["url"]["system_url"]
        except Exception as e:
            logger.warning(f"VeFaaS cloudAPP could not get endpoint. Error: {e}")
            vefaas_endpoint = ""
        return vefaas_endpoint

    def _get_vefaas_application_id_by_name(self) -> str:
        if not self.vefaas_application_name:
            raise ValueError(
                "VeFaaS CloudAPP must be set application_name to get application_id."
            )
        from veadk.integrations.ve_faas.ve_faas import VeFaaS

        vefaas_client = VeFaaS(
            access_key=getenv("VOLCENGINE_ACCESS_KEY"),
            secret_key=getenv("VOLCENGINE_SECRET_KEY"),
        )
        vefaas_application_id = vefaas_client.find_app_id_by_name(
            self.vefaas_application_name
        )
        return vefaas_application_id

    async def _get_a2a_client(self) -> A2AClient:
        interceptors: list[ClientCallInterceptor] = [
            AuthInterceptor(self.credential_service)
        ]

        if self.use_agent_card:
            http_auth_scheme_data = {
                "type": "http",
                "bearer_format": "jwt",
                "scheme": "Bearer",
            }
            http_auth_scheme = HTTPAuthSecurityScheme.model_validate(
                http_auth_scheme_data
            )
            resolver = A2ACardResolver(
                httpx_client=self.httpx_client,
                base_url=self.vefaas_endpoint,  # 这里的base_url是用来获取agent_card的...
            )

            final_agent_card_to_use: AgentCard | None = None
            _public_card = (
                await resolver.get_agent_card()
            )  # Fetches from default public path
            final_agent_card_to_use = _public_card
            final_agent_card_to_use.security = [{"http_auth": []}]
            final_agent_card_to_use.security_schemes = {
                "http_auth": SecurityScheme(root=http_auth_scheme)
            }
            final_agent_card_to_use.url = self.vefaas_endpoint
            return A2AClient(
                httpx_client=self.httpx_client,
                agent_card=final_agent_card_to_use,
                interceptors=interceptors,
            )
        else:
            return A2AClient(
                httpx_client=self.httpx_client,
                url=self.vefaas_endpoint,
                interceptors=interceptors,
            )

    def update_self(
        self,
        volcengine_ak: str = getenv("VOLCENGINE_ACCESS_KEY"),
        volcengine_sk: str = getenv("VOLCENGINE_SECRET_KEY"),
    ):
        if not volcengine_ak or not volcengine_sk:
            raise ValueError("Volcengine access key and secret key must be set.")

        # TODO(floritange): support update cloud app

    def delete_self(
        self,
        volcengine_ak: str = getenv("VOLCENGINE_ACCESS_KEY"),
        volcengine_sk: str = getenv("VOLCENGINE_SECRET_KEY"),
    ):
        if not volcengine_ak or not volcengine_sk:
            raise ValueError("Volcengine access key and secret key must be set.")

        if not self.vefaas_application_id:
            self.vefaas_application_id = self._get_vefaas_application_id_by_name()

        confirm = input(
            f"Confirm delete cloud app {self.vefaas_application_id}? (y/N): "
        )
        if confirm.lower() != "y":
            print("Delete cancelled.")
            return
        else:
            from veadk.integrations.ve_faas.ve_faas import VeFaaS

            vefaas_client = VeFaaS(access_key=volcengine_ak, secret_key=volcengine_sk)
            vefaas_client.delete(self.vefaas_application_id)
            print(
                f"Cloud app {self.vefaas_application_id} delete request has been sent to VeFaaS"
            )
            while True:
                try:
                    id = self._get_vefaas_application_id_by_name()
                    if not id:
                        break
                    time.sleep(3)
                except Exception as _:
                    break
            print("Delete application done.")

    async def message_send(
        self,
        message: str,
        session_id: str,
        user_id: str,
        timeout: float = 600.0,
        bearer_token: str | None = None,
    ) -> Message | None:
        """
        timeout is in seconds, default 600s (10 minutes)

        params:
            bearer_token: the token to authenticate the user.
        """
        await self.credential_service.set_credentials(
            session_id=session_id,
            security_scheme_name="http_auth",
            credential=bearer_token,
        )

        a2a_client = await self._get_a2a_client()
        auth_client = InteractiveAuthClient(
            a2a_client=a2a_client,
            httpx_client=self.httpx_client,
            auth_handler=handle_auth,
            use_agent_card=self.use_agent_card,  # 保持你的原始设置
        )

        # 替换原始的 request() 调用
        return await auth_client.send_message_with_auth(
            message=message,
            user_id=user_id,
            session_id=session_id,
            timeout=timeout,
        )

        # async def request():
        #     send_message_payload: dict[str, Any] = {
        #         "message": {
        #             "role": "user",
        #             "parts": [{"type": "text", "text": message}],
        #             "messageId": uuid4().hex,
        #         },
        #         "metadata": {
        #             "user_id": user_id,
        #             "session_id": session_id,
        #         },
        #     }
        #     try:
        #         message_send_request = SendMessageRequest(
        #             id=uuid4().hex,
        #             params=MessageSendParams(**send_message_payload),
        #         )

        #         res = await a2a_client.send_message(
        #             message_send_request,
        #             context=ClientCallContext(state={'http_kwargs': {"timeout": httpx.Timeout(timeout)},'sessionId': session_id})
        #         )

        #         logger.debug(
        #             f"Message sent to cloud app {self.vefaas_application_name} with response: {res}"
        #         )

        #         # we ignore type checking here, because the response
        #         # from CloudApp will not be `Task` type
        #         return res.root.result  # type: ignore
        #     except Exception as e:
        #         # TODO(floritange): show error log on VeFaaS function
        #         print(e)
        #         return None

        # if not self.use_agent_card:
        #     async with self.httpx_client:
        #         return await request()
        # return await request()


def get_message_id(message: Message):
    """Get the messageId of the a2a message"""
    if getattr(message, "messageId", None):
        # Compatible with the messageId of the old a2a-python version (<0.3.0) in cloud app
        return message.messageId  # type: ignore
    else:
        return message.message_id
