from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model
# Create your models here.
class User(AbstractUser):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)


    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]
    def __str__(self):
        return self.email

class Category(models.Model):
    name=models.CharField(max_length=100,unique=True)
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE, related_name='children')

    def __str__(self):
        return self.name
 

class Products(models.Model):
    category = models.ManyToManyField(Category, related_name='products')
    name=models.CharField(max_length=100)
    description=models.TextField()
    price=models.FloatField()
    quantity=models.IntegerField()
    image = models.ImageField(upload_to='products_images/')  

    def __str__(self):
        return self.name


class CartItem(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE) 
    product=models.ManyToManyField(Products)
    quantity = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f"{self.user.username} - {self.product.name}"

class Order(models.Model):
    ORDER_STATUS_CHOICES = [
    ('processing', 'Processing'),
    ('shipped', 'Shipped'),
    ('delivered', 'Delivered'),
    ('canceled', 'Canceled'),
]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    order_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, choices=ORDER_STATUS_CHOICES, default='processing')

    def __str__(self):
        return f"{self.user.username} - Order {self.id}"

    def calculate_total_amount(self):
        total_amount = sum(item.product.price * item.quantity for item in self.orderitem_set.all())
        return total_amount    

class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    product = models.ForeignKey(Products, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    price_at_order_creation = models.DecimalField(max_digits=10, decimal_places=2)
