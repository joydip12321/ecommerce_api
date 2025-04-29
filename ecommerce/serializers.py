from rest_framework import serializers
from .models import Vendor, Product, Order, OrderItem
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['email', 'first_name', 'last_name', 'role', 'password']
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = get_user_model().objects.create_user(password=password, **validated_data)
        return user

class CustomLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'), email=email, password=password)
            if not user:
                raise serializers.ValidationError("Invalid email or password.")
        else:
            raise serializers.ValidationError("Both email and password are required.")

        data['user'] = user
        return data

class VendorSerializer(serializers.ModelSerializer):
    user = UserSerializer()

    class Meta:
        model = Vendor
        fields = ['id', 'user']

class ProductSerializer(serializers.ModelSerializer):
    vendor = VendorSerializer(read_only=True) 

    class Meta:
        model = Product
        fields = ['id', 'name', 'description', 'price', 'vendor']

class OrderItemSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField()  
    product = ProductSerializer(read_only=True)

    class Meta:
        model = OrderItem
        fields = ['id', 'product', 'quantity', 'status']

    def update(self, instance, validated_data):
        user = self.context.get('request').user

        if user.role == 'vendor':
            status = validated_data.get('status')
            if status:
                instance.status = status
                instance.save()
                return instance
            else:
                raise serializers.ValidationError("Vendors can only update the status.")
        return super().update(instance, validated_data)


class OrderSerializer(serializers.ModelSerializer):
    order_items = OrderItemSerializer(many=True, read_only=False)
    customer = UserSerializer(read_only=True)

    class Meta:
        model = Order
        fields = ['id', 'customer', 'order_items']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get('request', None)
        if request and hasattr(request, "user"):
            user = request.user
            if user.role == 'customer':
                self.fields['order_items'].read_only = True
            elif user.role == 'vendor':
                self.fields['order_items'].read_only = False

    def get_order_items(self, obj):
        request = self.context.get('request')
        user = request.user
        if user.role == 'vendor':
            return OrderItemSerializer(
                obj.order_items.filter(product__vendor=user.vendor_profile),
                many=True
            ).data
        return OrderItemSerializer(obj.order_items.all(), many=True).data

    def create(self, validated_data):
        order_items_data = validated_data.pop('order_items')
        order = Order.objects.create(**validated_data)
        for item_data in order_items_data:
            OrderItem.objects.create(order=order, **item_data)
        return order

    def update(self, instance, validated_data):
        user = self.context.get('request').user

        if user.role == 'vendor':
            order_items_data = validated_data.get('order_items', None)

            if order_items_data:
                for item_data in order_items_data:
                    item_id = item_data.get('id')
                    if not item_id:
                        raise serializers.ValidationError("OrderItem 'id' is required to update the status.")

                    try:
                        item = OrderItem.objects.get(id=item_id, order=instance)
                    except OrderItem.DoesNotExist:
                        raise serializers.ValidationError(f"OrderItem with id {item_id} does not exist.")

                    serializer = OrderItemSerializer(
                        instance=item,
                        data=item_data,
                        partial=True,
                        context=self.context
                    )
                    serializer.is_valid(raise_exception=True)
                    serializer.save()
            else:
                raise serializers.ValidationError("Vendors can only update the 'status' of order items.")
        else:
            return super().update(instance, validated_data)

        instance.refresh_from_db()
        return instance
