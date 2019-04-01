from django.db import models

# Create your models here.
class Image(models.Model):
    image = models.ImageField(blank=False)

    def __str__(self):
        return str(self.image)

    def getURL(self):
        return self.image.url

class Node(models.Model):
    image = models.ForeignKey(Image, on_delete=models.CASCADE, blank=True, null=True)
    ip = models.CharField(max_length=24, primary_key=True)
    pNode = models.ForeignKey("self", on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return str(self.ip)

