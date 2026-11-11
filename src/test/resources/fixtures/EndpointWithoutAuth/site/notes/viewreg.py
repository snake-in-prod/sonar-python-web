from django.urls import path

from .registry import registry


def register_view(model, name="", path=None, detail=True):
    def wrapper(cls):
        key = model.__name__.lower()
        registry["views"].setdefault(key, []).append({"view": cls, "name": name, "path": name if path is None else path, "detail": detail})
        return cls

    return wrapper


def get_view_urls(app_label, model_name, detail=True):
    views = [v for v in registry["views"].get(model_name, []) if v["detail"] == detail]
    return [path(f"{v['path']}/" if v["path"] else "", v["view"].as_view()) for v in views]
