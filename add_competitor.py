from competitor_parser import CompetitorTracker

def add_new_competitor():
    name = input("Введите название конкурента: ")
    rss_url = input("Введите URL RSS-ленты: ")
    views_xpath = input("Введите XPath для просмотров: ")
    date_xpath = input("Введите XPath для даты публикации: ")
    
    tracker = CompetitorTracker()
    tracker.add_competitor(name, rss_url, views_xpath, date_xpath)
    print(f"Конкурент {name} успешно добавлен!")

if __name__ == "__main__":
    add_new_competitor()