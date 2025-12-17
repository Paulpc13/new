# 1. Standard Python Library Imports
import json
import random # Para generar códigos de reserva
import smtplib
import traceback
import uuid

# 2. Third-Party Library Imports (Django REST Framework)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework.permissions import BasePermission, SAFE_METHODS, AllowAny, IsAuthenticated
from rest_framework.decorators import action, api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication



from rest_framework.authtoken.models import Token

# 3. Django Library Imports
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.shortcuts import redirect, get_object_or_404, render # get_object_or_404 importado una vez
from django.db import transaction # IMPORTANTE PARA CONFIRMAR RESERVA
from django.http import HttpResponse
from django.db.models import Q
from django.utils import timezone
from django.core.mail import send_mail, EmailMessage # EmailMessage importado una vez
from django.template.loader import render_to_string
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError


# IMPORTAMOS MODELOS Y SERIALIZERS

from django.http import HttpResponse
from rest_framework.authtoken.models import Token
from django.db.models import Q
from django.utils import timezone
from django.shortcuts import get_object_or_404
from .models import EmailVerificationToken
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.shortcuts import render, get_object_or_404
import uuid
from django.conf import settings
from django.core.mail import EmailMessage
import smtplib
import traceback
import uuid
from .models import RegistroUsuario, EmailVerificationToken
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError






# 4. Local App Imports (Models and Serializers)
from .models import (
    RegistroUsuario, EmailVerificationToken, # Los modelos RegistroUsuario y Token de verificación
    Promocion, Categoria, Servicio, Combo, ComboServicio,
    HorarioDisponible, Reserva, DetalleReserva, Pago, Cancelacion,
    Carrito, ItemCarrito 
)

from .serializers import (
    RegistroUsuarioSerializer, PromocionSerializer, CategoriaSerializer, ServicioSerializer,
    ComboDetailSerializer, ComboServicioSerializer, HorarioDisponibleSerializer, ReservaSerializer,
    DetalleReservaSerializer, PagoSerializer, CancelacionSerializer,
    CarritoSerializer, ItemCarritoSerializer
)




def enviar_correo(asunto, mensaje, destinatario, proveedor='gmail'):
    """
    Envía correo usando la configuración de Django. Intenta usar el backend
    de Django (`EmailMessage.send()`), y si hay error hace un fallback a smtplib
    usando la configuración del proveedor.
    """
    if proveedor == 'gmail':
        config = settings.EMAIL_GMAIL
    elif proveedor == 'outlook':
        config = settings.EMAIL_OUTLOOK
    elif proveedor == 'brevo':
        config = None
    else:
        raise ValueError("Proveedor no soportado")

    # Determinar remitente de forma segura: primero DEFAULT_FROM_EMAIL, luego USERNAME del config si existe
    default_from = getattr(settings, 'DEFAULT_FROM_EMAIL', None)
    if not default_from:
        default_from = config.get('USERNAME') if config else None

    email = EmailMessage(
        subject=asunto,
        body=mensaje,
        from_email=default_from,
        to=[destinatario],
    )
    email.content_subtype = "plain"

    try:
        # Si se solicita Brevo, preferimos API si está configurada, sino usamos SMTP relay
        if proveedor == 'brevo':
            api_key = getattr(settings, 'BREVO_API_KEY', '')
            if api_key:
                import requests
                payload = {
                    "sender": {"name": "No-Reply", "email": getattr(settings, 'DEFAULT_FROM_EMAIL', None)},
                    "to": [{"email": destinatario}],
                    "subject": asunto,
                    "textContent": mensaje,
                }
                headers = {
                    'api-key': api_key,
                    'Content-Type': 'application/json'
                }
                resp = requests.post('https://api.sendinblue.com/v3/smtp/email', json=payload, headers=headers, timeout=10)
                print(f"BREVO RESPONSE: {resp.status_code} {resp.text}") # DEBUG LOG
                if resp.status_code >= 400:
                    raise RuntimeError(f'Brevo API error: {resp.status_code} {resp.text}')
                return
            # si no hay API key, usar SMTP relay configurado en settings.EMAIL_BREVO
            brevo_cfg = getattr(settings, 'EMAIL_BREVO', {})
            if not brevo_cfg or not brevo_cfg.get('USERNAME'):
                raise RuntimeError('Brevo no configurado: neither BREVO_API_KEY nor EMAIL_BREVO SMTP credentials are set')
            # enviar por SMTP relay
            import smtplib
            with smtplib.SMTP(brevo_cfg['HOST'], brevo_cfg['PORT']) as server:
                if brevo_cfg.get('USE_TLS'):
                    server.starttls()
                server.login(brevo_cfg['USERNAME'], brevo_cfg['PASSWORD'])
                server.sendmail(brevo_cfg['USERNAME'], [destinatario], email.message().as_string())
            return

        # Usar el backend configurado en settings (recomendado)
        email.send(fail_silently=False)
    except Exception as e:
        # Si el proveedor es Brevo no intentamos fallback SMTP con una config inexistente;
        # re-levantar para que el llamante vea el error y lo loguee.
        if proveedor == 'brevo':
            raise
        # Fallback directo con smtplib si el backend falla
        try:
            import smtplib
            with smtplib.SMTP(config['HOST'], config['PORT']) as server:
                if config.get('USE_TLS'):
                    server.starttls()
                server.login(config['USERNAME'], config['PASSWORD'])
                server.sendmail(config['USERNAME'], [destinatario], email.message().as_string())
        except Exception:
            # Re-levantar para que el código llamante lo vea y lo pueda loguear
            raise





def home(request):
    return redirect('http://localhost:5173/login')

# ==========================================
# 1. AUTENTICACIÓN
# ==========================================
class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        usuario = request.data.get('usuario')
        clave = request.data.get('clave')
        
        # 1. Verificar si el usuario existe
        try:
            user_obj = User.objects.get(username=usuario)
        except User.DoesNotExist:
            return Response({'message': 'Credenciales inválidas'}, status=status.HTTP_401_UNAUTHORIZED)

        # 2. Verificar contraseña
        if not user_obj.check_password(clave):
            return Response({'message': 'Credenciales inválidas'}, status=status.HTTP_401_UNAUTHORIZED)
            
        # 3. Verificar si está activo (email verificado)
        if not user_obj.is_active:
            return Response({'message': 'El correo no ha sido verificado. Revisa tu bandeja de entrada.'}, status=status.HTTP_403_FORBIDDEN)

        # 4. Login exitoso
        token, created = Token.objects.get_or_create(user=user_obj)
        cliente = RegistroUsuario.objects.filter(email=user_obj.email).first()
        cliente_id = cliente.id if cliente else None

        return Response({
            'id': user_obj.id,
            'cliente_id': cliente_id,
            'username': user_obj.username,
            'is_admin': user_obj.is_staff,
            'token': token.key
        }, status=status.HTTP_200_OK)





class RegistroUsuarioView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self,request):
         try:
            nombre = request.data.get('nombre', '').strip()
            email = request.data.get('email', '').strip()
            clave = request.data.get('clave', '').strip()
            apellido = request.data.get('apellido', '').strip()
            telefono = request.data.get('telefono', '').strip()
            
            # 1️⃣, 2️⃣, 3️⃣ Validaciones de campos obligatorios e email
            if not nombre or not email or not clave:
                return Response(
                    {'message': 'Campos obligatorios faltantes.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            try:
                validate_email(email)
            except ValidationError:
                return Response({'message': 'Email inválido.'}, status=status.HTTP_400_BAD_REQUEST)

            # 4️⃣ Validar contraseña
            if len(clave) < 6:
                return Response({'message': 'La contraseña debe tener al menos 6 caracteres.'}, status=status.HTTP_400_BAD_REQUEST)

            # 5️⃣ Verificar si usuario o email existen
            if User.objects.filter(username=nombre).exists():
                return Response({'message': 'Ese usuario ya existe.'}, status=status.HTTP_400_BAD_REQUEST)
            if User.objects.filter(email=email).exists():
                return Response({'message': 'Ese correo ya está registrado.'}, status=status.HTTP_400_BAD_REQUEST)

            # 6️⃣ Crear usuario inactivo
            # Si hay un signal (señal) configurado, esta acción creará automáticamente un RegistroUsuario
            user = User.objects.create_user(username=nombre, email=email, password=clave)
            user.is_active = False
            user.save()
            
            # =========================================================================
            # 7️⃣ CORRECCIÓN DE INTEGRITYERROR: 
            #    Intentar obtener y actualizar, si falla, crear.
            # =========================================================================
            try:
                # Intentar obtener el RegistroUsuario creado por el signal automático
                registro = RegistroUsuario.objects.get(user=user)
                
                # Actualizar los campos que el signal podría no haber llenado
                registro.nombre = nombre # Sincroniza el nombre
                registro.apellido = apellido
                registro.telefono = telefono
                registro.save()
            
            except RegistroUsuario.DoesNotExist:
                # Si no se creó automáticamente, se crea manualmente
                registro = RegistroUsuario.objects.create(
                    user=user,
                    nombre=nombre,
                    apellido=apellido,
                    telefono=telefono
                )
            # =========================================================================

            # 8️⃣ Crear token de verificación
            token = str(uuid.uuid4())
            EmailVerificationToken.objects.create(user=user, token=token)


            # 9️⃣ Enviar correo de verificación
            link_verificacion = f"http://127.0.0.1:8000/api/verificar-email/?token={token}"
            try:
                # Renderizar template HTML
                html_message = render_to_string('fiesta/email_verificacion.html', {
                    'nombre': nombre,
                    'link_verificacion': link_verificacion
                })
                
                # Usa el backend configurado (SMTP Brevo)
                email_msg = EmailMessage(
                    subject='🎈 Verifica tu correo - Burbujitas de Colores',
                    body=html_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to=[email]
                )
                email_msg.content_subtype = 'html' # Enviar como HTML
                email_msg.send(fail_silently=False)
            except Exception:
                print("ERROR AL ENVIAR CORREO:")
                traceback.print_exc()

            
            # 9️⃣ Enviar correo de verificación (HTML)
            link_verificacion = f"http://127.0.0.1:8000/api/verificar-email/?token={token}"
            
            # Contexto para el template
            context = {
                'nombre': nombre,
                'link_verificacion': link_verificacion
            }
            
            # Renderizar el HTML
            html_message = render_to_string('emails/verification_email.html', context)
            plain_message = f"Hola {nombre}, verifica tu correo aquí: {link_verificacion}"

            try:
                send_mail(
                    subject='🎈 Verifica tu correo - Burbujitas de Colores',
                    message=plain_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    html_message=html_message,
                    fail_silently=False
                )
                print(f"✅ CORREO HTML ENVIADO A: {email}")
            except Exception as e:
                print(f"❌ ERROR AL ENVIAR CORREO: {str(e)}")
                # traceback.print_exc() # Opcional: descomentar si se quiere log completo


            # 1️⃣0️⃣ Respuesta exitosa
            return Response({'message': 'Usuario registrado correctamente. Revisa tu correo para verificar tu cuenta.'})

         except IntegrityError as e:
            # Captura errores de unicidad (como duplicados de email o teléfono si estuvieran configurados)
            print("ERROR DE BASE DE DATOS:")
            traceback.print_exc()
            return Response({'message': 'Error en base de datos. Usuario o correo ya registrado.', 'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

         except Exception as e:
            print("ERROR INESPERADO EN REGISTRO USUARIO:")
            traceback.print_exc()
            return Response({'message': 'Error inesperado', 'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class SendTestEmailView(APIView):
    """Enviar un correo de prueba usando el backend configurado (SendGrid/SMTP/Console)."""
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        to_email = request.data.get('email') or request.query_params.get('email')
        if not to_email:
            return Response({'error': 'El campo "email" es requerido (body JSON o query param).'}, status=status.HTTP_400_BAD_REQUEST)

        subject = request.data.get('subject', 'Correo de prueba Django')
        body = request.data.get('body', 'Este es un correo de prueba enviado desde la API de prueba.')

        try:
            # Usar el backend configurado en settings (SMTP Brevo)
            email = EmailMessage(
                subject=subject, 
                body=body, 
                to=[to_email], 
                from_email=settings.DEFAULT_FROM_EMAIL
            )
            email.content_subtype = 'plain'
            email.send(fail_silently=False)
            
            return Response({'message': 'Correo enviado via SMTP.'}, status=status.HTTP_200_OK)
        except Exception as e:
            traceback.print_exc()
            return Response({'error': 'Fallo al enviar correo', 'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerificarEmailView(APIView):
    """
    Verifica el correo de un usuario usando un token enviado por email.
    URL: /verificar-email/?token=<token>
    """


class VerificarEmailView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        token_value = request.query_params.get('token')
        if not token_value:

            return Response({'error': 'El parámetro "token" es obligatorio.'}, status=status.HTTP_400_BAD_REQUEST)

        # Buscar el token
        token_obj = get_object_or_404(EmailVerificationToken, token=token_value)

        # Revisar si ha expirado
        if token_obj.is_expired():
            return Response({'error': 'El token ha expirado.'}, status=status.HTTP_400_BAD_REQUEST)

        # Marcar usuario como activo/verificado (opcional)
        token_obj.user.is_active = True
        token_obj.user.save()

        # Opcional: eliminar el token para que no pueda reutilizarse
        token_obj.delete()

        # Renderizar página de éxito
        return render(request, 'fiesta/verificacion_exito.html')
        return Response({'error': 'Falta el token'}, status=400)

        # Buscar el token en la base de datos
        token_obj = get_object_or_404(EmailVerificationToken, token=token_value)

        # 1. Activar al usuario
        user = token_obj.user
        user.is_active = True
        user.save()
        
        # 2. Generar el Token de sesión (para el Frontend)
        auth_token, _ = Token.objects.get_or_create(user=user)
        
        # 3. Borrar el token de email ya usado
        token_obj.delete()

        # 4. RENDERIZAR PÁGINA DE ÉXITO (Redirección automática en el HTML)
        return render(request, 'emails/verification_success.html')




class RegistroUsuarioViewSet(viewsets.ModelViewSet):
    queryset = RegistroUsuario.objects.all()
    serializer_class = RegistroUsuarioSerializer

# ==========================================
# 2. PERMISOS Y CATÁLOGO
# ==========================================
class SoloLecturaOAdmin(BasePermission):
    def has_permission(self, request, view):
        return (request.method in SAFE_METHODS or (request.user and request.user.is_staff))

class SoloUsuariosAutenticados(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

class CategoriaViewSet(viewsets.ModelViewSet):
    queryset = Categoria.objects.all()
    serializer_class = CategoriaSerializer
    permission_classes = [SoloLecturaOAdmin]

class PromocionViewSet(viewsets.ModelViewSet):
    queryset = Promocion.objects.all()
    serializer_class = PromocionSerializer
    permission_classes = [SoloLecturaOAdmin]

class ServicioViewSet(viewsets.ModelViewSet):
    queryset = Servicio.objects.all()
    serializer_class = ServicioSerializer
    permission_classes = [SoloLecturaOAdmin]

class ComboViewSet(viewsets.ModelViewSet):
    queryset = Combo.objects.all()
    serializer_class = ComboDetailSerializer
    permission_classes = [SoloLecturaOAdmin]

class ComboServicioViewSet(viewsets.ModelViewSet):
    queryset = ComboServicio.objects.all()
    serializer_class = ComboServicioSerializer

# ==========================================
# 3. GESTIÓN DE RESERVAS
# ==========================================
class HorarioDisponibleViewSet(viewsets.ModelViewSet):
    queryset = HorarioDisponible.objects.all()
    serializer_class = HorarioDisponibleSerializer
    permission_classes = [SoloLecturaOAdmin]
    
    @action(detail=False, methods=['get'], permission_classes=[AllowAny])
    def disponibles(self, request):
        fecha = request.query_params.get('fecha')
        if not fecha: return Response({'error': 'Falta fecha'}, status=400)
        
        horarios = HorarioDisponible.objects.filter(fecha=fecha, disponible=True)
        libres = []
        for h in horarios:
            confirmadas = Reserva.objects.filter(horario=h, estado__in=['CONFIRMADA', 'PENDIENTE']).count()
            if confirmadas < h.capacidad_reserva:
                libres.append(h)
        return Response(HorarioDisponibleSerializer(libres, many=True).data)

class ReservaViewSet(viewsets.ModelViewSet):
    queryset = Reserva.objects.all()
    serializer_class = ReservaSerializer
    permission_classes = [SoloUsuariosAutenticados]

class DetalleReservaViewSet(viewsets.ModelViewSet):
    queryset = DetalleReserva.objects.all()
    serializer_class = DetalleReservaSerializer

class PagoViewSet(viewsets.ModelViewSet):
    queryset = Pago.objects.all()
    serializer_class = PagoSerializer
    permission_classes = [SoloUsuariosAutenticados]

class CancelacionViewSet(viewsets.ModelViewSet):
    queryset = Cancelacion.objects.all()
    serializer_class = CancelacionSerializer

    permission_classes = [SoloUsuariosAutenticados]

# ==========================================
# 4. GESTIÓN DEL CARRITO COMPLETA
# ==========================================

# A. Vista para agregar items
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def agregar_al_carrito(request):
    print("--- INTENTO DE AGREGAR AL CARRITO ---")
    
    try:
        # 1. Obtener datos estandarizados
        tipo = request.data.get('tipo') 
        item_id = request.data.get('item_id')
        cantidad = int(request.data.get('cantidad', 1))

        if not tipo or not item_id:
            return Response({'error': 'Faltan datos: tipo o item_id requeridos'}, status=400)

        # 2. Identificar Cliente
        cliente = RegistroUsuario.objects.filter(email=request.user.email).first()
        if not cliente:
            return Response({'error': 'No se encontró tu perfil de cliente.'}, status=404)

        # 3. Buscar/Crear Carrito
        carrito, _ = Carrito.objects.get_or_create(cliente=cliente)

        # 4. Identificar Producto y Precio
        servicio_obj = None
        combo_obj = None
        precio = 0

        if tipo == 'servicio':
            servicio_obj = get_object_or_404(Servicio, pk=item_id)
            precio = servicio_obj.precio_base
        elif tipo == 'combo':
            combo_obj = get_object_or_404(Combo, pk=item_id)
            precio = combo_obj.precio_combo
        
        if not servicio_obj and not combo_obj:
            return Response({'error': 'Producto no encontrado'}, status=404)

        # 5. Guardar en Carrito (Upsert)
        item, created = ItemCarrito.objects.get_or_create(
            carrito=carrito,
            servicio=servicio_obj,
            combo=combo_obj,
            defaults={'precio_unitario': precio, 'cantidad': 0}
        )
        
        item.cantidad += cantidad
        item.precio_unitario = precio 
        item.save()

        return Response({
            'mensaje': 'Producto agregado correctamente', 
            'item': ItemCarritoSerializer(item).data
        }, status=200)

    except Exception as e:
        print(f"ERROR CARRITO: {str(e)}")
        return Response({'error': str(e)}, status=500)

# B. Vista para confirmar y convertir en Reserva
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def confirmar_carrito(request):
    print("--- CONFIRMANDO RESERVA ---")
    try:
        # Datos del formulario
        fecha_evento = request.data.get('fecha_evento')
        direccion = request.data.get('direccion_evento')
        
        if not fecha_evento or not direccion:
            return Response({'error': 'Fecha y dirección son obligatorias'}, status=400)

        cliente = RegistroUsuario.objects.filter(email=request.user.email).first()
        carrito = Carrito.objects.filter(cliente=cliente).first()

        if not carrito or not carrito.items.exists():
            return Response({'error': 'El carrito está vacío'}, status=400)

        # Calcular Totales
        subtotal_total = sum(item.subtotal for item in carrito.items.all())
        impuestos = float(subtotal_total) * 0.12 # Ejemplo 12%
        total = float(subtotal_total) + impuestos

        # Asignar un horario disponible (Lógica simplificada: toma el primero del día)
        # Nota: Idealmente el usuario debería elegir el bloque horario específico
        horario = HorarioDisponible.objects.filter(fecha=fecha_evento).first()
        
        if not horario:
            # Si no hay horarios creados para ese día, no se puede reservar
            return Response({'error': f'No hay disponibilidad abierta para el {fecha_evento}'}, status=400)

        # Transacción Atómica: O se guarda todo (reserva + detalles) o nada.
        with transaction.atomic():
            # 1. Crear Reserva
            nueva_reserva = Reserva.objects.create(
                cliente=cliente,
                horario=horario,
                codigo_reserva=f"RES-{random.randint(1000,9999)}-{uuid.uuid4().hex[:4].upper()}",
                fecha_evento=fecha_evento,
                fecha_inicio=horario.hora_inicio,
                direccion_evento=direccion,
                subtotal=subtotal_total,
                impuestos=impuestos,
                total=total,
                estado='PENDIENTE'
            )

            # 2. Mover items de Carrito a DetalleReserva
            for item in carrito.items.all():
                DetalleReserva.objects.create(
                    reserva=nueva_reserva,
                    tipo='S' if item.servicio else 'C',
                    servicio=item.servicio,
                    combo=item.combo,
                    cantidad=item.cantidad,
                    precio_unitario=item.precio_unitario,
                    subtotal=item.subtotal
                )
            
            # 3. Vaciar Carrito
            carrito.items.all().delete()

        return Response({
            'mensaje': 'Reserva creada con éxito', 
            'codigo': nueva_reserva.codigo_reserva
        }, status=201)

    except Exception as e:
        print(f"ERROR CONFIRMACION: {str(e)}")
        return Response({'error': str(e)}, status=500)

# C. ViewSet para gestionar el carrito (Ver)
class CarritoViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Carrito.objects.all()
    serializer_class = CarritoSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated:
            return Carrito.objects.filter(cliente__email=user.email)
        return Carrito.objects.none()

# D. ViewSet para gestionar items individuales (Eliminar)
class ItemCarritoViewSet(viewsets.ModelViewSet):
    queryset = ItemCarrito.objects.all()
    serializer_class = ItemCarritoSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Solo permite gestionar items de TU propio carrito
        if self.request.user.is_authenticated:
            return ItemCarrito.objects.filter(carrito__cliente__email=self.request.user.email)
        return ItemCarrito.objects.none()

