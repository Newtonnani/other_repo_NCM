from django.contrib import admin
from .models import *

# admin.site.register(ExtendUser)

class PaytmHistoryAdmin(admin.ModelAdmin):
    list_display = ( 'user' , 'MID', 'TXNAMOUNT', 'STATUS')


admin.site.register(PaytmHistory, PaytmHistoryAdmin)