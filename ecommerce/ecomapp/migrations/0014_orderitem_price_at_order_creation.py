# Generated by Django 4.2.4 on 2023-08-20 16:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ecomapp', '0013_remove_orderitem_price_at_order_creation'),
    ]

    operations = [
        migrations.AddField(
            model_name='orderitem',
            name='price_at_order_creation',
            field=models.DecimalField(decimal_places=2, default=1, max_digits=10),
            preserve_default=False,
        ),
    ]
