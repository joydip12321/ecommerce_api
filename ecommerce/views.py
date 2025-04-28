from django.shortcuts import render
from rest_framework import viewsets
from .models import Vendor, Product, Order, OrderItem
from .serializers import VendorSerializer, ProductSerializer, OrderSerializer,LoginSerializer
from .permissions import IsAdmin, IsVendor, IsCustomer 
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics, permissions
from django.contrib.auth import get_user_model
from .serializers import UserSerializer
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate

class RegisterView(generics.CreateAPIView):
    permission_classes = [AllowAny]
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        if user.role == 'vendor':
            Vendor.objects.create(user=user, store_name="Your Store Name")  

class LoginView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        user = authenticate(email=email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return Response({
                'refresh': str(refresh),
                'access': access_token,
                'user': {
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'role': user.role,
                }
            }, status=status.HTTP_200_OK)

        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
class LogoutView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get('refresh')

        if not refresh_token:
            return Response({"detail": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Successfully logged out"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": f"Invalid refresh token. {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

class VendorViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAdmin]
    queryset = Vendor.objects.all()
    serializer_class = VendorSerializer

class ProductViewSet(viewsets.ModelViewSet):
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated]  

    def get_permissions(self):

        if self.action in ['create', 'update', 'destroy']:
            permission_classes = [IsVendor | IsAdmin]  
        else:
            permission_classes = [IsAuthenticated] 
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):

        if self.request.user.role == 'vendor':
            serializer.save(vendor=self.request.user.vendor_profile)

    def get_queryset(self):
        user = self.request.user
        if user.role == 'vendor':
            if hasattr(user, 'vendor_profile'):
                return Product.objects.filter(vendor=user.vendor_profile)
            else:
                return Product.objects.none()
        elif user.role == 'admin':
            return Product.objects.all()
        else:
            return Product.objects.all()



class OrderViewSet(viewsets.ModelViewSet):
    serializer_class = OrderSerializer

    def get_permissions(self):
        if self.action == 'create':
            permission_classes = [IsCustomer]
        else:
            permission_classes = [IsVendor | IsAdmin] 
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        serializer.save(customer=self.request.user)

    def get_queryset(self):
        user = self.request.user

        if user.role == 'customer':
            return Order.objects.filter(customer=user)

        if user.role == 'vendor':

            if hasattr(user, 'vendor_profile'):
                return Order.objects.filter(
                    order_items__product__vendor=user.vendor_profile
                ).distinct()
            else:
                return Order.objects.none()

        if user.role == 'admin':
            return Order.objects.all()

        return Order.objects.none()


