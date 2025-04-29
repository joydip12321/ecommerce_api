from rest_framework import viewsets, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView, GenericAPIView
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError

from .models import Vendor, Product, Order
from .serializers import VendorSerializer, ProductSerializer, OrderSerializer, CustomLoginSerializer, UserSerializer
from .permissions import IsAdmin, IsVendor, IsCustomer
from .utils import BlacklistedToken  

def get_user_from_token(token_str):
    token = AccessToken(token_str)
    user_id = token['user_id']
    return get_user_model().objects.get(id=user_id)


class RegisterView(CreateAPIView):
    permission_classes = [AllowAny]
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        if user.role == 'vendor':
            Vendor.objects.create(user=user)


class CustomLoginView(GenericAPIView):
    serializer_class = CustomLoginSerializer
    authentication_classes = []
    permission_classes = []

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })


class CustomLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            raise AuthenticationFailed("Refresh token is required.")

        try:
            token = RefreshToken(refresh_token)
            blacklisted_token = BlacklistedToken(token=refresh_token)
            blacklisted_token.blacklist_token()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)

        except TokenError as e:
            raise AuthenticationFailed(f"Invalid token: {str(e)}")


class VendorViewSet(viewsets.ModelViewSet):
    serializer_class = VendorSerializer

    def get_permissions(self):
        if self.action in ['create', 'update', 'destroy']:
            permission_classes = [IsVendor]
        elif self.action in ['list', 'retrieve']:
            permission_classes = [IsAdmin | IsVendor]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        if self.request.user.role == 'vendor':
            serializer.save(user=self.request.user)

    def get_queryset(self):
        user = self.request.user
        if user.role == 'vendor':
            return Vendor.objects.filter(user=user)
        elif user.role == 'admin':
            return Vendor.objects.all()
        return Vendor.objects.none()


class ProductViewSet(viewsets.ModelViewSet):
    serializer_class = ProductSerializer

    def get_permissions(self):
        if self.action in ['create', 'update', 'destroy']:
            permission_classes = [IsVendor]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        if self.request.user.role == 'vendor':
            serializer.save(vendor=self.request.user.vendor_profile)

    def get_queryset(self):
        user = self.request.user
        if user.role == 'vendor' and hasattr(user, 'vendor_profile'):
            return Product.objects.filter(vendor=user.vendor_profile)
        elif user.role == 'admin':
            return Product.objects.all()
        return Product.objects.all()


class OrderViewSet(viewsets.ModelViewSet):
    serializer_class = OrderSerializer

    def get_permissions(self):
        if self.action == 'create':
            permission_classes = [IsCustomer]
        elif self.action in ['update', 'destroy']:
            permission_classes = [IsVendor]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        serializer.save(customer=self.request.user)

    def get_queryset(self):
        user = self.request.user
        if user.role == 'customer':
            return Order.objects.filter(customer=user)
        elif user.role == 'vendor' and hasattr(user, 'vendor_profile'):
            return Order.objects.filter(order_items__product__vendor=user.vendor_profile).distinct()
        elif user.role == 'admin':
            return Order.objects.all()
        return Order.objects.none()
