from rest_framework import serializers
from .models import Vendor, Product, Order, OrderItem
from django.contrib.auth import get_user_model

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['email', 'first_name', 'last_name', 'role', 'password']
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = get_user_model().objects.create_user(password=password, **validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class VendorSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = Vendor
        fields = ['id', 'store_name', 'user']

class ProductSerializer(serializers.ModelSerializer):
    vendor = VendorSerializer(read_only=True) 

    class Meta:
        model = Product
        fields = ['id', 'name', 'description', 'price', 'vendor']


class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ['id', 'product', 'quantity', 'price']

class OrderSerializer(serializers.ModelSerializer):
    order_items = OrderItemSerializer(many=True)
    customer=UserSerializer(read_only=True) 
    class Meta:
        model = Order
        fields = ['id', 'customer', 'status', 'order_items']

    def create(self, validated_data):
        order_items_data = validated_data.pop('order_items')
        order = Order.objects.create(**validated_data)
        for item_data in order_items_data:
            OrderItem.objects.create(order=order, **item_data)
        return order

