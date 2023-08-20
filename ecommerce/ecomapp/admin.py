from django.contrib import admin
from . models import Category,Products,OrderItem
# Register your models here.
admin.site.register(Products)
admin.site.register(Category)
admin.site.register(OrderItem)