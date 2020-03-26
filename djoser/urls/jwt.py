from django.conf.urls import url
from rest_framework_simplejwt import views

urlpatterns = [
    url(r"^jwt/create/?", views.TokenObtainPairView.as_view(), name="jwt-create"),
    url(r"^jwt/refresh/?", views.TokenRefreshView.as_view(), name="jwt-refresh"),
    url(r"^jwt/verify/?", views.TokenVerifyView.as_view(), name="jwt-verify"),
    #mi login con el code
    # url(r"^jwt/create_token_with_code/?", views.Code_TokenObtainPairView.as_view(), name="jwt-create_token_with_code"),
]

#agregaremos aqui la extencion del JWT por que pip no consigue resolver las dependencias entre 
#tantos paquetes personalizados
from djoser.code_token_auth import Code_TokenObtainPairView

urlpatterns=urlpatterns+[
    url(r"^jwt/create_token_with_code/?", Code_TokenObtainPairView.as_view(), name="jwt-create_token_with_code"),
]

