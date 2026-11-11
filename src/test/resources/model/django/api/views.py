from rest_framework import permissions, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response


class ArticleViewSet(viewsets.ModelViewSet):
    def create(self, request):
        return Response(request.data)

    @action(detail=True, methods=["post"])
    def publish(self, request, pk=None):
        return Response({"id": pk})


class PublicViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.AllowAny]


@api_view(["GET", "POST"])
@permission_classes([permissions.AllowAny])
def ping(request):
    return Response({"pong": True})
