from ipwhois import IPWhois
import pyshark

def extract_destination_ips(pcap_file):
    try:
        # Открытие pcapng-файла
        capture = pyshark.FileCapture(pcap_file)

        # Список для хранения уникальных IP-адресов
        destination_ips = set()

        # Обход каждого пакета
        for packet in capture:
            try:
                # Проверяем, есть ли IP-слой
                if 'IP' in packet:
                    # Добавляем адрес назначения в множество
                    destination_ips.add(packet.ip.dst)
            except AttributeError:
                # Игнорируем пакеты без IP-слоя
                continue

        # Закрытие файла захвата
        capture.close()

        return list(destination_ips)
    except Exception as e:
        return {"error": f"Ошибка обработки файла: {e}"}

def get_ip_owner(ip_address):
    try:
        # Создаем объект для IP-адреса
        obj = IPWhois(ip_address)
        # Выполняем запрос к сервису whois
        result = obj.lookup_rdap()

        # Извлекаем интересующую информацию
        owner = result.get('network', {}).get('name', 'Не найдено')
        country = result.get('network', {}).get('country', 'Не указана')
        description = result.get('network', {}).get('remarks', 'Нет описания')

        # Форматируем вывод
        return {
            "IP": ip_address,
            "Владелец": owner,
            "Страна": country,
            "Описание": description,
        }
    except Exception as e:
        return {"error": f"Ошибка при обработке IP-адреса {ip_address}: {e}"}


def format_results(data):
    formatted_result = []
    for entry in data:
        ip = entry.get("IP", "Не указан")
        owner = entry.get("Владелец", "Не указан")
        country = entry.get("Страна", "Не указана")
        descriptions = entry.get("Описание", [])

        # Форматирование описания
        description_text = ""
        if descriptions:
            for desc in descriptions:
                title = desc.get("title", "Описание")
                description = desc.get("description", "Нет данных")
                description_text += f"  - {title}: {description}\n"
        else:
            description_text = "  Нет дополнительных данных.\n"

        # Форматируем блок для каждого IP
        formatted_result.append(
            f"IP-адрес: {ip}\n"
            f"  Владелец: {owner}\n"
            f"  Страна: {country}\n"
            f"  Дополнительная информация:\n{description_text}"
        )

    return "\n" + "\n".join(formatted_result)

# Пример использования
if __name__ == "__main__":
    result = []
    pcap_file_path = r"<FILE.pcapng>"
    ip_list = extract_destination_ips(pcap_file_path)
    for ip in ip_list:
        result.append(get_ip_owner(ip))
    print(format_results(result))