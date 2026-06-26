"""
Authentication paths
"""
from asyncio.log import logger
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Request

from ...core.user_manager import UserManager
from ...core.user_manager_v2 import UserManagerV2
from ...core.exceptions import (
    UserNotFoundError,
    UserAlreadyExistsError,
    AuthenticationError,
    InvalidSecretError
)
from ..models import (
    RegisterRequest,
    RegisterV2Request,
    LoginInitRequest,
    LoginInitV2Request,
    LoginVerifyRequest,
    LoginVerifyV2Request,
    AuthInitResponse,
    AuthResponse,
    MessageResponse,
    ErrorResponse
)
from ..dependencies import (
    get_current_user, 
    get_user_manager, 
    get_user_manager_v2, 
    get_limiter
)

from ..dependencies import limiter as rate_limiter

router = APIRouter(prefix="/auth", tags=["Authentication"])

# ============================================================
# V1 ROUTES (Legacy)
# ============================================================

@router.post(
    "/register",
    response_model=MessageResponse,
    responses={
        400: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("10/minute")
async def register(
    request: Request,
    user_data: RegisterRequest,
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """V1: Register a new user (legacy)."""
    try:
        user_id = user_manager.register_user(
            user_data.master_secret,
            user_data.user_data or {}
        )
        
        return MessageResponse(
            message="User registered successfully",
            data={"user_id": user_id}
        )
        
    except InvalidSecretError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except UserAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )


@router.post(
    "/login/init",
    response_model=AuthInitResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("30/minute")
async def login_init(
    request: Request,
    login_data: LoginInitRequest,
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """V1: Initiate login (legacy)."""
    try:
        challenge = user_manager.initiate_login(login_data.master_secret)
        
        return AuthInitResponse(
            challenge=challenge,
            message="Please decrypt the challenge and submit it with /verify"
        )
        
    except InvalidSecretError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login initiation failed: {str(e)}"
        )


@router.post(
    "/login/verify",
    response_model=AuthResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("30/minute")
async def login_verify(
    request: Request,
    verify_data: LoginVerifyRequest,
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """V1: Verify login (legacy)."""
    try:
        session = user_manager.complete_login(
            verify_data.master_secret,
            verify_data.challenge_response
        )
        
        return AuthResponse(
            user_id=session.user_id,
            session_id=session.user_id,
            expires_at=session.expires_at,
            message="Authentication successful"
        )
        
    except InvalidSecretError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login verification failed: {str(e)}"
        )


# ============================================================
# V2 ROUTES (Zero-Knowledge-Inspired)
# ============================================================

@router.post(
    "/register_v2",
    response_model=MessageResponse,
    responses={
        400: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("10/minute")
async def register_v2(
    request: Request,
    register_data: RegisterV2Request,
    user_manager_v2: UserManagerV2 = Depends(get_user_manager_v2)
) -> Any:
    """
    V2: Register a new user (Zero-Knowledge-Inspired).
    
    The user_id is derived from master_secret on the client side.
    The server NEVER sees the master_secret.
    """
    try:
        
        result = user_manager_v2.register_user_v2(
            register_data.user_id,
            register_data.user_data or {}
        )
        
        return MessageResponse(
            message="User registered successfully (V2)",
            data={"user_id": result}
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except UserAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )


@router.post(
    "/login/init_v2",
    response_model=AuthInitResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("30/minute")
async def login_init_v2(
    request: Request,
    init_data: LoginInitV2Request,
    user_manager_v2: UserManagerV2 = Depends(get_user_manager_v2)
) -> Any:
    """
    V2: Initiate login - returns encrypted challenge.
    
    The client must decrypt this challenge using the master_secret.
    """
    try:
        
        challenge_token = user_manager_v2.initiate_login_v2(init_data.user_id)
        
        return AuthInitResponse(
            challenge=challenge_token,
            message="Please decrypt the challenge and submit it with /verify_v2"
        )
        
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login initiation failed: {str(e)}"
        )


@router.post(
    "/login/verify_v2",
    response_model=AuthResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("30/minute")
async def login_verify_v2(
    request: Request,
    verify_data: LoginVerifyV2Request,
    user_manager_v2: UserManagerV2 = Depends(get_user_manager_v2)
) -> Any:
    """
    V2: Verify login - decrypts and verifies the challenge.
    
    The client sends the encrypted challenge back.
    The server decrypts it using Flash512 and verifies it.
    """
    try:
    
        session = user_manager_v2.complete_login_v2(
            verify_data.user_id,
            verify_data.challenge_response
        )
        
        return AuthResponse(
            user_id=session.user_id,
            session_id=session.user_id,
            expires_at=session.expires_at,
            message="Authentication successful (V2)"
        )
        
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login verification failed: {str(e)}"
        )



@router.post(
    "/logout",
    response_model=MessageResponse,
    responses={
        401: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("60/minute")
async def logout(
    request: Request,
    user_id: str = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager),
    user_manager_v2: UserManagerV2 = Depends(get_user_manager_v2)
) -> Any:
    """Logout user."""
    try:
        logger.info(f"Logout request for user: {user_id[:16]}...")
        
        if hasattr(user_manager_v2, '_sessions') and user_id in user_manager_v2._sessions:
            user_manager_v2.logout(user_id)
            logger.info(f"Logout successful (V2) for user: {user_id[:16]}...")
        elif hasattr(user_manager, '_sessions') and user_id in user_manager._sessions:
            user_manager.logout(user_id)
            logger.info(f"Logout successful (V1) for user: {user_id[:16]}...")
        else:
            logger.warning(f"No active session found for user: {user_id[:16]}...")
            return MessageResponse(
                message="No active session found"
            )
        
        return MessageResponse(
            message="Logged out successfully"
        )
        
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}"
        )