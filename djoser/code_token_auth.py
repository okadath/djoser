from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers

from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.state import User
from rest_framework_simplejwt.tokens import RefreshToken, SlidingToken, UntypedToken
from .auth_backend import PasswordlessAuthBackend
from .models import  Code,User_Code
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate, login
from django.core.exceptions import ValidationError

#los serializers heredan de esta clase
class TokenObtainSerializer(serializers.Serializer):
    default_error_messages = {
        'no_active_account': _('No active account found with the given credentials')
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # self.fields[self.username_field] = serializers.CharField()
        # self.fields['password'] = PasswordField()
        self.fields["code"] = serializers.CharField()


    def validate(self, attrs):
        print("validando")
        authenticate_kwargs = {
            'code': attrs['code'],
        }
        print(attrs)
        print(attrs["code"])

        try:
            cod = attrs["code"]
            try:
                print("codigo existente")
                print(cod) 
                exist_code=Code.objects.get(code=cod)

                print(exist_code) 
                try:
                    username=get_object_or_404(User_Code , code=exist_code.id).user.username
                except Exception as e:
                    raise ValidationError("codigo sin usuario: {}".format(cod))
            except Exception as e:
                raise ValidationError("codigo invalido: {}".format(cod))
            
            user = PasswordlessAuthBackend.authenticate(user=username)

        except KeyError:
            pass

        self.user = user
        if self.user is None or not self.user.is_active:
            raise exceptions.AuthenticationFailed(
                self.error_messages['no_active_account'],
                'no_active_account',
            )

        return {}

    @classmethod
    def get_token(cls, user):
        raise NotImplementedError('Must implement `get_token` method for `TokenObtainSerializer` subclasses')

#mi metodo
class Code_TokenObtainPairSerializer(TokenObtainSerializer):
    @classmethod
    def get_token(cls, user):
        return RefreshToken.for_user(user)

    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        return data



from rest_framework import generics, status
from rest_framework.response import Response

# from rest_framework_simplejwt import serializers
from rest_framework_simplejwt.authentication import AUTH_HEADER_TYPES
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


class TokenViewBase(generics.GenericAPIView):
    permission_classes = ()
    authentication_classes = ()

    serializer_class = None

    www_authenticate_realm = 'api'

    def get_authenticate_header(self, request):
        return '{0} realm="{1}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        print("data in tokenviewbase")
        print(request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(serializer.validated_data, status=status.HTTP_200_OK)






class Code_TokenObtainPairView(TokenViewBase):
    """
    Login personalizado para los usuarios con un codigo comprado
    funciona igual que el login por password pero a partir de un codigo(sin proporcionar el usuario)
    input:{"code":"mi codigo"}
    output:{
  "access": "TOKEN",
  "refresh": "TOKEN"
}
    """
    serializer_class = Code_TokenObtainPairSerializer


token_obtain_pair = Code_TokenObtainPairView.as_view()