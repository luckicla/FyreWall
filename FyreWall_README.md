# 🔥 FyreWall v2.1

Gestor de Firewall, Monitor de Puertos, **Bloqueo Anti-Vigilancia de Aula** y Monitor de Peticiones de Red.

---

## Pestañas disponibles

| Pestaña     | Comando     | Descripción                                      |
|-------------|-------------|--------------------------------------------------|
| ⌨️ Terminal  | (siempre)   | Consola de comandos. No se puede cerrar.         |
| 🔍 Monitor  | `monitor`   | Debug Monitor de conexiones activas              |
| 🏫 Aula     | `aula`      | Bloqueo de Faronics Insight y Reboot Restore     |
| 📡 Peticiones | `peticiones` | Monitor visual de peticiones de red en vivo    |

Las pestañas se pueden abrir también con los botones de la barra superior, y cerrarse con el ✕.

---

## Comandos de consola

### Puertos
```
block-port <puerto> [tcp|udp] [in|out]   Bloquear un puerto
unblock-port <puerto> [tcp|udp] [in|out] Desbloquear un puerto
status <puerto>                           Ver estado de un puerto
list                                      Listar todos los puertos bloqueados por FyreWall
flush                                     Eliminar TODAS las reglas de FyreWall
```

### Aplicaciones y procesos
```
block-app <ruta_exe>         Bloquear una app por ruta de ejecutable
block-process <nombre>       Bloquear un proceso en ejecución
```

### Vigilancia de aula
```
block-insight                Bloquear Faronics Insight Student (todos sus puertos y procesos)
unblock-insight              Desbloquear Faronics Insight
block-reboot                 Bloquear Reboot Restore Enterprise
unblock-reboot               Desbloquear Reboot Restore
```

### Red
```
isolate                      Bloquear TODO el tráfico de red
unisolate                    Restaurar la red
scan                         Re-escanear conexiones en el Monitor
```

### Pestañas
```
peticiones                   Abrir pestaña de peticiones de red
monitor                      Abrir el Debug Monitor
aula                         Abrir el panel de Bloqueo de Aula
```

### General
```
clear                        Limpiar la consola
help                         Mostrar ayuda completa
```

---

## Pestaña Peticiones

Muestra en tiempo real las aplicaciones con conexiones de red activas:

```
📦 chrome.exe  PID 1234   ──<>──────────────   🖥️ DESKTOP-ABC
               TCP  192.168.1.5:52341 → 216.58.201.14:443   ESTABLISHED
```

- La línea `──<>──` se anima cuando hay paquetes en tránsito
- `<>` = 1-2 conexiones, `</>` = 5+, `<///>` = 10+
- Botón **🔒 Bloquear aplicación** en cada tarjeta
- Se actualiza automáticamente cada 3 segundos (pausable)

---

## Bloqueo de aula persistente

Para que el bloqueo **sobreviva a Reboot Restore** (que restaura el disco al reiniciar):

1. Haz clic en **🔒 BLOQUEAR TODO** para aplicar las reglas
2. Haz clic en **⏰ Crear tarea de inicio** → se crea una tarea de Windows Scheduler bajo SYSTEM
3. La tarea re-aplica las reglas en cada arranque, **antes** de que Reboot Restore restaure el disco

---

## Puertos bloqueados

### Faronics Insight Student
| Puerto       | Protocolo | Dirección | Descripción                    |
|--------------|-----------|-----------|--------------------------------|
| 796          | UDP+TCP   | IN+OUT    | Legacy (versiones antiguas)    |
| 11796        | UDP+TCP   | IN+OUT    | Insight moderno (>v7.8)        |
| 1053         | UDP       | IN+OUT    | Status broadcast               |
| 8888-8890    | TCP       | IN+OUT    | WebSocket cifrado (v11+)       |
| 10000-20000  | TCP       | IN+OUT    | Control remoto dinámico        |

### Reboot Restore Enterprise
| Puerto       | Protocolo | Dirección | Descripción                    |
|--------------|-----------|-----------|--------------------------------|
| 9000         | TCP       | IN+OUT    | Endpoint Manager (default)     |
| 5900         | TCP       | IN+OUT    | VNC / Remote Control           |
| 9001, 9010   | TCP       | IN+OUT    | Puertos alternativos           |

---

## Requisitos

- Windows 10/11
- Python 3.11+
- Pillow: `pip install pillow`
- **Ejecutar como Administrador** para operaciones de firewall

## Ejecutar

```bat
FyreWall.bat
```
o directamente:
```
python fyrewall.py
```
