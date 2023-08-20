from django.shortcuts import render
from django.conf import settings
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, login, logout
from .serializers import UserSerializer,CategorySerializer,ProductsSerializer,ProductsViewSerializer,CartItemSerializer
from rest_framework import generics
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from . models import Category,Products,CartItem,Order,OrderItem
from django.contrib.auth import get_user_model
from .serializers import OrderSerializer, CartItemSerializer
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .serializers import PasswordResetSerializer
from django.utils import encoding
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from . models import User
from django.utils.encoding import force_bytes, force_str
from django.shortcuts import redirect
from django.db.models import Q
from .pagination import CustomPagination
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import generics, permissions
from .serializers import UserDetailSerializer
from rest_framework.decorators import api_view, permission_classes
from django.template.loader import render_to_string
from .serializers import PromotionalEmailSerializer
from django.core.mail import EmailMultiAlternatives
from django.template.loader import get_template
from django.utils.html import strip_tags
from rest_framework.generics import ListAPIView
from django.shortcuts import render
from django.views.generic import TemplateView
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings


User = get_user_model()



class LandingPageView(TemplateView):
    template_name = 'landing.html'


class AdminLoginView(TokenObtainPairView):
    pass  

class UserRegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            ctx = {
                'user': user.username,
            }
            subject = "Welcome to Our E-commerce Platform"
            email_template = get_template('welcome_email.html')
            email_content = email_template.render(ctx)
            from_email = settings.DEFAULT_FROM_EMAIL
            to_email = user.email
            send_mail(subject, '', from_email, [to_email], html_message=email_content)

            return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            refresh = RefreshToken.for_user(user)
            return Response({'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
from rest_framework_simplejwt.views import TokenObtainPairView

class UserLogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)

class PasswordResetRequestView(APIView):
    permission_classes=[IsAuthenticated]
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                token_generator = PasswordResetTokenGenerator()
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = token_generator.make_token(user)
                reset_link = f'http://127.0.0.1:8000/user/password-reset-confirm/{uid}/{token}/'
                ctx = {
                    'user': user.username,
                    'reset_link': reset_link,
                    'uid': uid,   
                    'token': token,   
                }
                subject = "Password Reset Request"
                email_template = get_template('password_reset_email.html')
                email_content = email_template.render(ctx)
                from_email = settings.DEFAULT_FROM_EMAIL
                to_email = user.email
                send_mail(subject, '', from_email, [to_email], html_message=email_content)
                return Response({'message': 'Password reset email sent successfully'}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'error': 'No user with that email address'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    permission_classes=[AllowAny]
    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            user = None

        if user is not None and PasswordResetTokenGenerator().check_token(user, token):
            new_password = request.data.get('new_password')
            if new_password:
                user.set_password(new_password)
                user.save()
                return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'New password is required'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

class CategoryListCreateView(generics.ListCreateAPIView):
    queryset=Category.objects.all()
    serializer_class=CategorySerializer

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAdminUser()]
        return [IsAuthenticated()]

class CategoryDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset=Category.objects.all()
    serializer_class=CategorySerializer
    permission_classes=[IsAdminUser]

class ProductsListCreateView(generics.ListCreateAPIView):
    queryset = Products.objects.all()
    pagination_class = CustomPagination

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAdminUser()]
        return [IsAuthenticated()]
    from decimal import Decimal


    def get_serializer_class(self):
        if self.request.method == 'POST':
            return ProductsSerializer
        else:
            return ProductsViewSerializer


    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    def update_product_prices(self, new_prices):
        for product_id, new_price in new_prices.items():
            try:
                product = Products.objects.get(pk=product_id)
                product.price = Decimal(new_price)
                product.save()
            except Products.DoesNotExist:
                pass    

    def get_queryset(self):
        queryset = super().get_queryset() 

        category_id = self.request.query_params.get('category')
        if category_id:
            queryset = queryset.filter(category__id=category_id)

        min_price = self.request.query_params.get('min_price')
        max_price = self.request.query_params.get('max_price')
        if min_price and max_price:
            queryset = queryset.filter(price__range=(min_price, max_price))

        attribute = self.request.query_params.get('attribute')
        if attribute:
            queryset = queryset.filter(attribute=attribute)

        return queryset

class ProductsDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset=Products.objects.all()
    serializer_class=ProductsSerializer

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAdminUser()]
        return [IsAuthenticated()]

def send_order_status_notification(order, old_status, new_status):
    subject = f'Order Status Update - Order {order.id}'
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = order.user.email

    html_template = get_template('order_status_update.html')
    context = {
        'username': order.user.username,
        'order_id': order.id,
        'old_status': old_status,
        'new_status': new_status,
    }
    html_content = html_template.render(context)

    email = EmailMultiAlternatives(subject, strip_tags(html_content), from_email, [to_email])
    email.attach_alternative(html_content, 'text/html')

    email.send()

class CartItemCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        products = request.data.get('products', [])
        quantities = request.data.get('quantity', [])

        if not products or not quantities:
            return Response({'error': 'Products and quantity are required'}, status=status.HTTP_400_BAD_REQUEST)

        cart_items = []
        for product_id, quantity in zip(products, quantities):
            try:
                product = Products.objects.get(pk=product_id)
                cart_item = CartItem(user=request.user, quantity=quantity)
                cart_item.save()
                cart_item.product.set([product])  
                cart_items.append(cart_item)
            except Products.DoesNotExist:
                pass  
        serializer = CartItemSerializer(cart_items, many=True)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class UserListView(generics.ListAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAdminUser]

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAdminUser]

class CartItemListView(APIView):
    permission_classes=[IsAuthenticated]
    def get(self, request):
        user = request.user 
        cart_items = CartItem.objects.filter(user=user)
        serializer = CartItemSerializer(cart_items, many=True)
        return Response(serializer.data)

    def delete(self, request):
        user = request.user 
        CartItem.objects.filter(user=user).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)  

class CartDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = CartItem.objects.all()
    serializer_class = CartItemSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        user = self.request.user
        return CartItem.objects.filter(user=user).first()



class OrderCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user

        cart_items = CartItem.objects.filter(user=user)
        if not cart_items:
            return Response({"error": "Your cart is empty"}, status=status.HTTP_400_BAD_REQUEST)

        order = Order.objects.create(user=user, status='processing')

        for cart_item in cart_items:
            products = cart_item.product.all()
            for product in products:
                OrderItem.objects.create(
                    order=order,
                    product=product,
                    quantity=cart_item.quantity,
                    price_at_order_creation=product.price  
                )
                product.quantity -= cart_item.quantity
                product.save()  
            cart_item.delete()

        serializer = OrderSerializer(order)

        send_order_notification(order) 
        return Response(serializer.data, status=status.HTTP_201_CREATED)

def send_order_notification(order):
    user_subject = f'Order Confirmation - Order {order.id}'
    admin_subject = f'New Order - Order {order.id}'

    user_email = order.user.email
    admin_email = settings.ADMIN_EMAIL

    try:
        user_message = render_to_string('order_notification.html', {'order_id': order.id})
        admin_message = render_to_string('order_notification.html', {'order_id': order.id})

        send_mail(
            user_subject,
            user_message,
            settings.DEFAULT_FROM_EMAIL,
            [user_email],
            fail_silently=False,
            html_message=user_message  # Pass the HTML message for user email
        )

        send_mail(
            admin_subject,
            admin_message,
            settings.DEFAULT_FROM_EMAIL,
            [admin_email],
            fail_silently=False,
            html_message=admin_message  # Pass the HTML message for admin email
        )
    except Exception as e:
        user_subject_error = f'Failed to send Order Confirmation Email - Order {order.id}'
        admin_subject_error = f'Failed to send New Order Email - Order {order.id}'

        print(f"Failed to send order notification email: {e}")
        print(f"Recipient: {user_email}")
        print(f"Recipient: {admin_email}")

        send_mail(user_subject_error, str(e), settings.DEFAULT_FROM_EMAIL, [user_email], fail_silently=False)
        send_mail(admin_subject_error, str(e), settings.DEFAULT_FROM_EMAIL, [admin_email], fail_silently=False)


class AdminOrderListView(ListAPIView):
    serializer_class = OrderSerializer
    permission_classes = [IsAdminUser]
    pagination_class = CustomPagination  
    def get_queryset(self):
        return Order.objects.all().order_by('-order_date')  


class UserOrderListView(ListAPIView):
    serializer_class = OrderSerializer
    pagination_class = CustomPagination  
    def get_queryset(self):
        user = self.request.user
        return Order.objects.filter(user=user).order_by('-order_date')  

@api_view(['POST'])
@permission_classes([IsAdminUser])
def send_promotional_email(request):
    if request.user.is_staff:
        serializer = PromotionalEmailSerializer(data=request.data)
        if serializer.is_valid():
            subject = serializer.validated_data['subject']
            message = serializer.validated_data['message']
            recipient_list = [user.email for user in get_user_model().objects.all()]

            html_message = render_to_string('promotional_email.html', {'message': message})

            try:
                send_mail(subject, '', 'athira99@gmail.com', recipient_list, html_message=html_message)
                return Response({'message': 'Promotional email sent successfully.'}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({'error': f'An error occurred while sending the email: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'You do not have permission to send promotional emails.'}, status=status.HTTP_403_FORBIDDEN)


@api_view(['PATCH'])
@permission_classes([IsAdminUser])
def update_order_status(request, pk):
    try:
        order = Order.objects.get(pk=pk)
    except Order.DoesNotExist:
        return Response({'error': 'Order not found.'}, status=status.HTTP_404_NOT_FOUND)

    new_status = request.data.get('status')
    if not new_status:
        return Response({'error': 'Status field is required.'}, status=status.HTTP_400_BAD_REQUEST)

    valid_statuses = [status[0] for status in Order.ORDER_STATUS_CHOICES]  

    if new_status in valid_statuses:
        old_status = order.status
        order.status = new_status
        order.save()

        send_order_status_notification(order, old_status, new_status)

        return Response({'message': f'Order status updated to "{new_status}" successfully.'}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Invalid status value.'}, status=status.HTTP_400_BAD_REQUEST)





