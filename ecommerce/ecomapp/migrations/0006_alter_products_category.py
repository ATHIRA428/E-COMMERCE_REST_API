# Generated by Django 4.2.3 on 2023-08-04 16:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ecomapp', '0005_rename_categories_products_category'),
    ]

    operations = [
        migrations.AlterField(
            model_name='products',
            name='category',
            field=models.ManyToManyField(null=True, related_name='products', to='ecomapp.category'),
        ),
    ]
