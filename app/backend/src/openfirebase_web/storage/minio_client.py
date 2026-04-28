from __future__ import annotations

import asyncio
from functools import lru_cache

import boto3
from botocore.client import Config

from ..config import get_settings


@lru_cache
def _client():
    settings = get_settings()
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        region_name=settings.s3_region,
        config=Config(signature_version="s3v4"),
    )


async def ensure_bucket() -> None:
    settings = get_settings()
    client = _client()

    def _ensure() -> None:
        try:
            client.head_bucket(Bucket=settings.s3_bucket)
        except client.exceptions.ClientError:
            client.create_bucket(Bucket=settings.s3_bucket)

    await asyncio.to_thread(_ensure)


async def object_exists(key: str) -> bool:
    settings = get_settings()
    client = _client()

    def _head() -> bool:
        try:
            client.head_object(Bucket=settings.s3_bucket, Key=key)
            return True
        except client.exceptions.ClientError:
            return False

    return await asyncio.to_thread(_head)


async def put_object(*, key: str, data: bytes) -> None:
    settings = get_settings()
    client = _client()
    await asyncio.to_thread(
        client.put_object, Bucket=settings.s3_bucket, Key=key, Body=data
    )


async def put_object_stream(*, key: str, fileobj) -> None:
    """Stream-upload a file-like to MinIO.

    boto3's ``upload_fileobj`` transparently switches to S3 multipart for
    large inputs (threshold ~8 MiB) and never buffers the full body in
    memory, so this handles multi-GB bundles without blowing the backend
    process's RSS. Caller is responsible for seeking ``fileobj`` to 0
    first and for ensuring the underlying stream is a binary file-like.
    """
    settings = get_settings()
    client = _client()
    await asyncio.to_thread(
        client.upload_fileobj, fileobj, settings.s3_bucket, key
    )


async def get_object(key: str) -> bytes:
    settings = get_settings()
    client = _client()

    def _get() -> bytes:
        resp = client.get_object(Bucket=settings.s3_bucket, Key=key)
        return resp["Body"].read()

    return await asyncio.to_thread(_get)


async def try_get_object(key: str) -> bytes | None:
    """Like ``get_object`` but returns None if the key doesn't exist."""
    settings = get_settings()
    client = _client()

    def _get() -> bytes | None:
        try:
            resp = client.get_object(Bucket=settings.s3_bucket, Key=key)
            return resp["Body"].read()
        except client.exceptions.NoSuchKey:
            return None
        except Exception:
            return None

    return await asyncio.to_thread(_get)


async def list_objects_detailed(prefix: str) -> list[dict[str, object]]:
    """Like ``list_objects`` but returns ``{"key", "size"}`` per object."""
    settings = get_settings()
    client = _client()

    def _list() -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        token: str | None = None
        while True:
            kwargs: dict[str, object] = {"Bucket": settings.s3_bucket, "Prefix": prefix}
            if token:
                kwargs["ContinuationToken"] = token
            resp = client.list_objects_v2(**kwargs)
            for obj in resp.get("Contents", []):
                out.append({"key": obj["Key"], "size": int(obj.get("Size", 0))})
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
        return out

    return await asyncio.to_thread(_list)


async def list_objects(prefix: str) -> list[str]:
    settings = get_settings()
    client = _client()

    def _list() -> list[str]:
        keys: list[str] = []
        token: str | None = None
        while True:
            kwargs = {"Bucket": settings.s3_bucket, "Prefix": prefix}
            if token:
                kwargs["ContinuationToken"] = token
            resp = client.list_objects_v2(**kwargs)
            for obj in resp.get("Contents", []):
                keys.append(obj["Key"])
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
        return keys

    return await asyncio.to_thread(_list)


async def delete_prefix(prefix: str) -> None:
    keys = await list_objects(prefix)
    for k in keys:
        await delete_object(k)


async def delete_object(key: str) -> None:
    settings = get_settings()
    client = _client()
    try:
        await asyncio.to_thread(
            client.delete_object, Bucket=settings.s3_bucket, Key=key
        )
    except Exception:
        pass


async def copy_object(src_key: str, dst_key: str) -> bool:
    """Server-side copy within the same bucket. Returns False if src missing."""
    settings = get_settings()
    client = _client()

    def _copy() -> bool:
        try:
            client.copy_object(
                Bucket=settings.s3_bucket,
                Key=dst_key,
                CopySource={"Bucket": settings.s3_bucket, "Key": src_key},
            )
            return True
        except client.exceptions.ClientError:
            return False

    return await asyncio.to_thread(_copy)


async def copy_prefix(src_prefix: str, dst_prefix: str) -> int:
    """Server-side copy every object under ``src_prefix`` → ``dst_prefix``."""
    keys = await list_objects(src_prefix)
    count = 0
    for k in keys:
        suffix = k[len(src_prefix):]
        if await copy_object(k, dst_prefix + suffix):
            count += 1
    return count
