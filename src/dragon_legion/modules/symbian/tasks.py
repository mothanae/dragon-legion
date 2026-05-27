"""Celery tasks for Symbian/Nokia feature phone modules."""

from celery import shared_task
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=2)
def execute_symbian_rom_dump(self, attack_id: str, device_id: str,
                             attack_vector: str, params: dict) -> dict:
    """Dump Symbian XIP ROM via serial AT commands."""
    logger.info("Dumping Symbian ROM for device %s", device_id)
    from dragon_legion.modules.symbian import SymbianROMDumper

    dumper = SymbianROMDumper(serial_port=params.get("port"))
    rom_data = dumper.dump_via_at()
    dumper.parse_rom(rom_data)
    dumper.close()
    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "symbian_rom_dump",
        "rom_size": len(rom_data),
    }


@shared_task(bind=True, max_retries=2)
def execute_sis_traversal(self, attack_id: str, device_id: str,
                          attack_vector: str, params: dict) -> dict:
    """Generate SIS directory traversal package."""
    logger.info("Generating SIS traversal for device %s", device_id)
    from dragon_legion.modules.symbian import SISExploit

    exploit = SISExploit()
    sis = exploit.generate_traversal_sis(
        target_path=params.get("target", "..\\System\\Libs\\efsrv.dll"),
        payload_data=bytes.fromhex(params.get("payload", "")),
    )
    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "symbian_sis",
        "sis_size": len(sis),
    }


@shared_task(bind=True, max_retries=2)
def execute_nokia_nk2_dump(self, attack_id: str, device_id: str,
                           attack_vector: str, params: dict) -> dict:
    """Dump Nokia feature phone flash via NK2 protocol."""
    logger.info("Dumping Nokia flash for device %s", device_id)
    from dragon_legion.modules.symbian import NokiaNK2Protocol

    nk2 = NokiaNK2Protocol(serial_port=params.get("port", "/dev/ttyUSB0"))
    if nk2.handshake():
        nk2.dump_flash(output_path=params.get("output", "nokia_dump.bin"))
        nk2.close()
        return {"attack_id": attack_id, "status": "completed", "module": "nokia_nk2"}
    nk2.close()
    return {"attack_id": attack_id, "status": "failed", "module": "nokia_nk2"}


@shared_task(bind=True, max_retries=2)
def execute_spi_flash_read(self, attack_id: str, device_id: str,
                           attack_vector: str, params: dict) -> dict:
    """Read SPI flash chip from dead Nokia device."""
    logger.info("Reading SPI flash for device %s", device_id)
    from dragon_legion.modules.symbian import SPIFlashReader

    reader = SPIFlashReader(programmer_type=params.get("programmer", "ch341a"))
    chip = reader.detect_chip()
    reader.read_flash(output_path=params.get("output", "spi_dump.bin"))
    return {
        "attack_id": attack_id,
        "status": "completed",
        "module": "nokia_spi",
        "chip": chip,
    }


@shared_task(bind=True, max_retries=2)
def execute_motorola_p2k(self, attack_id: str, device_id: str,
                         attack_vector: str, params: dict) -> dict:
    """Access Motorola P2K filesystem."""
    logger.info("Accessing Motorola P2K for device %s", device_id)
    from dragon_legion.modules.symbian import MotorolaP2K

    p2k = MotorolaP2K(serial_port=params.get("port", "/dev/ttyUSB0"))
    if p2k.enter_p2k_mode():
        listing = p2k.list_dir("/a/")
        p2k.close()
        return {"attack_id": attack_id, "status": "completed", "module": "motorola_p2k", "listing": listing}
    p2k.close()
    return {"attack_id": attack_id, "status": "failed", "module": "motorola_p2k"}


@shared_task(bind=True, max_retries=2)
def execute_siemens_at(self, attack_id: str, device_id: str,
                       attack_vector: str, params: dict) -> dict:
    """Access Siemens phone via extended AT commands."""
    logger.info("Accessing Siemens for device %s", device_id)
    from dragon_legion.modules.symbian import SiemensAT

    siemens = SiemensAT(serial_port=params.get("port", "/dev/ttyUSB0"))
    info = siemens.get_sysinfo()
    siemens.close()
    return {"attack_id": attack_id, "status": "completed", "module": "siemens_at", "sysinfo": info}


@shared_task(bind=True, max_retries=2)
def execute_se_obex(self, attack_id: str, device_id: str,
                    attack_vector: str, params: dict) -> dict:
    """Access Sony Ericsson via Bluetooth OBEX."""
    logger.info("Accessing Sony Ericsson OBEX for device %s", device_id)
    from dragon_legion.modules.symbian import SonyEricssonOBEX

    obex = SonyEricssonOBEX()
    bt_addr = params.get("bt_address", "")
    if obex.connect(bt_addr):
        obex.close()
        return {"attack_id": attack_id, "status": "completed", "module": "sony_ericsson_obex"}
    return {"attack_id": attack_id, "status": "failed", "module": "sony_ericsson_obex"}
