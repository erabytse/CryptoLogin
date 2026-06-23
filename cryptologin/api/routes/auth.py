"""
Routes d'authentification
"""
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse

from ...core.user_manager import UserManager
from ...core.exceptions import (
    UserNotFoundError,
    UserAlreadyExistsError,
    AuthenticationError,
    InvalidSecretError
)
from ..models import (
    RegisterRequest,
    LoginInitRequest,
    LoginVerifyRequest,
    AuthInitResponse,
    AuthResponse,
    MessageResponse,
    ErrorResponse
)
from ..dependencies import get_user_manager, get_current_user
from ..dependencies import limiter as rate_limiter

router = APIRouter(prefix="/auth", tags=["Authentication"])


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
    request: Request,  # Ajouté pour rate_limiter
    user_data: RegisterRequest,
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """Register a new user."""
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
    request: Request,  # Ajouté pour rate_limiter
    login_data: LoginInitRequest,
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """Initiate the login process."""
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
    request: Request,  # Ajouté pour rate_limiter
    verify_data: LoginVerifyRequest,
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """Verify the challenge response and create a session."""
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
    request: Request,  # Ajouté pour rate_limiter
    user_id: str = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """Log out the user."""
    try:
        user_manager.logout(user_id)
        return MessageResponse(
            message="Logged out successfully"
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}"
        )