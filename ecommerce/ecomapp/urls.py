from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    CategoryListCreateView, CartDetailView, CategoryDetailView,
    ProductsListCreateView, ProductsDetailView, CartItemCreateView, CartItemListView,
    UserRegistrationView, UserLoginView, UserLogoutView, AdminLoginView,
    update_order_status, UserOrderListView, AdminOrderListView, send_promotional_email,
    OrderCreateView, PasswordResetRequestView, PasswordResetConfirmView,
    UserListView, LandingPageView, UserDetailView
)

urlpatterns = [
    path('', LandingPageView.as_view()),
    path('register/', UserRegistrationView.as_view()),
    path('login/', UserLoginView.as_view()),
    path('login-admin/', AdminLoginView.as_view(), name='admin_login'),
    path('logout/', UserLogoutView.as_view()),
    path('categories/create/', CategoryListCreateView.as_view()),
    path('categories/<int:pk>/', CategoryDetailView.as_view()),
    path('products/create/', ProductsListCreateView.as_view()),
    path('products/list/admin/', ProductsListCreateView.as_view()),
    path('products/<int:pk>/update/', ProductsDetailView.as_view()),
    path('orders/list/admin/', AdminOrderListView.as_view(), name='admin-order-list'),
    path('orders/<int:pk>/update-status/', views.update_order_status, name='update-order-status'),
    path('user/products/list/', ProductsListCreateView.as_view()),
    path('products/create/admin/', ProductsListCreateView.as_view()),
    path('user/products/<int:pk>/', ProductsDetailView.as_view()),
    path('user/addcartitem/', CartItemCreateView.as_view()),
    path('user/view/cartitem/', CartItemListView.as_view()),
    path('user/cart/update/<int:pk>/', CartDetailView.as_view(), name='cart-detail'),
    path('user/order/place/', OrderCreateView.as_view()),
    path('users/list/admin/', UserListView.as_view(), name='user-list'),
    path('users/<int:pk>/update/', UserDetailView.as_view(), name='user-detail'),
    path('users/<int:pk>/delete/', UserDetailView.as_view(), name='user-detail'),
    path('user/password_reset_request/', PasswordResetRequestView.as_view()),
    path('user/password-reset-confirm/<str:uidb64>/<str:token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('user/order/', UserOrderListView.as_view(), name='user-order-list'),
    path('send-promotional-email/', send_promotional_email, name='send-promotional-email'),
]
