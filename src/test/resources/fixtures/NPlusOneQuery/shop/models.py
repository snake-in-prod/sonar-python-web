from django.db import models


class Customer(models.Model):
    name = models.CharField(max_length=100)


class Tag(models.Model):
    label = models.CharField(max_length=20)


class Stamped(models.Model):
    created_by = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name="+")

    class Meta:
        abstract = True


class Order(Stamped):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    tags = models.ManyToManyField(Tag)
    paid = models.BooleanField(default=False)
    objects = models.Manager()


class Item(models.Model):
    order = models.ForeignKey("shop.Order", on_delete=models.CASCADE, related_name="items")
    sku = models.CharField(max_length=20)


class Profile(models.Model):
    customer = models.OneToOneField(Customer, on_delete=models.CASCADE)


class InvoiceManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().select_related("customer")


class Invoice(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    objects = InvoiceManager()
