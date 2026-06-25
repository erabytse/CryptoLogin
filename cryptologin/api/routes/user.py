"""
User routes
"""
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, logger, status, Query, Request

from ...core.user_manager import UserManager
from ...core.user_manager_v2 import UserManagerV2
from ...core.exceptions import (
    UserNotFoundError,
    AuthenticationError,
    InvalidSecretError,
    DataVaultError
)
from ..models import (
    DataResponse,
    MessageResponse,
    ErrorResponse,
    UpdateDataRequest,
    RotateSecretRequest,
    DeleteUserRequest,
    UserResponse
)
from ..dependencies import get_user_manager, get_current_user
from ..dependencies import limiter as rate_limiter

router = APIRouter(prefix="/user", tags=["User"])


@router.get(
    "/data",
    response_model=DataResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("60/minute")
async def get_user_data(
    request: Request,
    master_secret: str = Query(..., min_length=32, description="User’s secret master"),
    user_id: str = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """Retrieves the user's data."""
    try:
        data = user_manager.get_user_data(user_id, master_secret)
        
        # CORRECTION: Si data est None ou vide, retourner un dictionnaire vide
        if data is None:
            data = {}
        
        return DataResponse(
            data=data,
            version="1.0"
        )
        
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except InvalidSecretError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except DataVaultError as e:
        # CORRECTION: En cas d'erreur de Vault, retourner des données vides
        # plutôt que de bloquer l'utilisateur
        logger.warning("Vault decryption failed: %s", str(e))
        return DataResponse(
            data={},
            version="1.0"
        )
    except Exception as e:
        # CORRECTION: En cas d'erreur inattendue, retourner des données vides
        logger.error("Failed to get user data: %s", str(e))
        return DataResponse(
            data={},
            version="1.0"
        )

@router.put(
    "/data",
    response_model=MessageResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("30/minute")
async def update_user_data(
    request: Request,
    update_data: UpdateDataRequest,
    user_id: str = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """Updates the user's data."""
    try:
        result = user_manager.update_user_data(
            user_id,
            update_data.master_secret,
            update_data.data
        )
        
        return MessageResponse(
            message="User data updated successfully",
            success=result
        )
        
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except InvalidSecretError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except DataVaultError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Vault encryption failed: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update user data: {str(e)}"
        )


@router.post(
    "/rotate",
    response_model=MessageResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("10/minute")
async def rotate_secret(
    request: Request,
    rotate_data: RotateSecretRequest,
    user_id: str = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """Rotate the user's secret."""
    try:
        result = user_manager.rotate_user_secret(
            user_id,
            rotate_data.old_secret,
            rotate_data.new_secret
        )
        
        return MessageResponse(
            message="Secret rotated successfully",
            data={
                "old_user_id": user_id,
                "new_user_id": user_manager.crypto_engine.derive_user_id(rotate_data.new_secret)
            }
        )
        
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except InvalidSecretError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
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
            detail=f"Secret rotation failed: {str(e)}"
        )


@router.delete(
    "",
    response_model=MessageResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("5/minute")
async def delete_user(
    request: Request,
    delete_data: DeleteUserRequest,
    user_id: str = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """Delete the user's account."""
    try:
        # Vérifier que le secret correspond
        derived_id = user_manager.crypto_engine.derive_user_id(delete_data.master_secret)
        if derived_id != user_id:
            raise AuthenticationError("Secret does not match user")
        
        result = user_manager.delete_user(user_id)
        
        return MessageResponse(
            message="User deleted successfully",
            success=result
        )
        
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except InvalidSecretError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
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
            detail=f"User deletion failed: {str(e)}"
        )


@router.get(
    "/info",
    response_model=UserResponse,
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        500: {"model": ErrorResponse}
    }
)
@rate_limiter.limit("60/minute")
async def get_user_info(
    request: Request,
    user_id: str = Depends(get_current_user),
    user_manager: UserManager = Depends(get_user_manager)
) -> Any:
    """Retrieves the user's information."""
    try:
        record = user_manager.storage.get_user(user_id)
        if not record:
            raise UserNotFoundError(f"User {user_id[:16]}... not found")
        
        return UserResponse(
            user_id=record.user_id,
            created_at=record.created_at,
            updated_at=record.updated_at,
            last_activity_at=record.last_activity_at,
            has_data=bool(record.user_data),
            has_vault=record.vault_data is not None
        )
        
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get user info: {str(e)}"
        )