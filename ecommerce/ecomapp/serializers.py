from rest_framework import serializers
from . models import Category,Products,CartItem,Order, OrderItem
from django.contrib.auth import get_user_model

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        return user

    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'email', 'first_name', 'last_name')

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()


class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['id', 'username', 'email', 'date_joined']

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model=Category
        fields= '__all__'

class ProductsViewSerializer(serializers.ModelSerializer):
    category=CategorySerializer(many=True)
    class Meta:
        model=Products
        fields= '__all__'

class ProductsSerializer(serializers.ModelSerializer):
    category = serializers.ListField(write_only=True)

    class Meta:
        model = Products
        fields = ('category', 'name', 'description', 'price', 'image', 'quantity',)

    def create(self, validated_data):
        category_names = validated_data.pop('category', [])
        product = Products.objects.create(**validated_data)

        for category_name in category_names:
            category, created = Category.objects.get_or_create(name=category_name)
            product.category.add(category)

        return product

    def validate_quantity(self, value):
        if value < 0:
            raise serializers.ValidationError("Quantity cannot be negative.")
        return value   

class CartItemSerializer(serializers.ModelSerializer):
    products = ProductsSerializer(many=True, read_only=True, source='product')

    class Meta:
        model = CartItem
        fields = ['id','products', 'quantity']

    def update(self, instance, validated_data):
        instance.quantity = validated_data.get('quantity', instance.quantity)
        instance.save()
        return instance

class OrderItemSerializer(serializers.ModelSerializer):
    product_details = ProductsSerializer(source='product', read_only=True)  

    class Meta:
        model = OrderItem
        fields = ['product_details', 'quantity'] 



class OrderSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    order_items = serializers.SerializerMethodField()
    total_amount = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = ['id', 'user', 'user_details', 'order_items', 'order_date', 'status', 'total_amount']
    def get_order_items(self, obj):
        order_items = obj.orderitem_set.all()
        order_item_data = OrderItemSerializer(order_items, many=True).data
        return order_item_data

    def get_total_amount(self, obj):
        return obj.calculate_total_amount()

    def get_user_details(self, obj):
        user = obj.user
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name
        }
        return user_data
    def get_order_items(self, obj):
        order_items = obj.orderitem_set.all()
        order_item_data = []

        for order_item in order_items:
            item_data = {
                'product': order_item.product.name,
                'price_per_unit': order_item.price_at_order_creation,  
                'quantity': order_item.quantity,
                'total_price': order_item.price_at_order_creation * order_item.quantity  
            }
            order_item_data.append(item_data)

        return order_item_data

class PromotionalEmailSerializer(serializers.Serializer):
    subject = serializers.CharField(max_length=200)
    message = serializers.CharField()

    def validate_subject(self, value):
        if not value:
            raise serializers.ValidationError("Subject is required.")
        return value

    def validate_message(self, value):
        if not value:
            raise serializers.ValidationError("Message content is required.")
        return value