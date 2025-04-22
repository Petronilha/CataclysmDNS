import dns.query
import dns.zone
from dns.exception import DNSException
from utils.logger import setup_logger

logger = setup_logger("zone_transfer")

def attempt_axfr(domain: str, nameserver: str) -> dict[str, str]:
    """
    Tenta transferência de zona (AXFR) no servidor especificado.
    """
    try:
        z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10))
        records = {}
        for name, node in z.nodes.items():
            rdatasets = node.rdatasets
            for rdataset in rdatasets:
                for rdata in rdataset:
                    fqdn = f"{name}.{domain}"
                    records.setdefault(str(rdataset.rdtype), []).append(f"{fqdn} -> {rdata}")
        logger.info(f"[+] AXFR bem-sucedido em {nameserver}")
        return records
    except DNSException as e:
        logger.warning(f"[-] AXFR falhou em {nameserver}: {e}")
        return {}