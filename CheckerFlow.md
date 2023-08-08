1. Создаём свой чекер AuthCheckerBearer:
    1. Наследуемся от AuthCheckerBase.
    2. Перегружаем CheckAuth (парсим и валидируем request, записываем информацию о юзере в request_context) и SupportsUserAuth (true).
    3. Добавляем поля AuthCache (ищем в нём спаршенный token) и vector<\UserScope> (тут хранятся необходимые для доступа spoce. Проверяем их наличие из спаршенного request).
2. Создаём CheckerFactory:
    1. Наследуемся от AuthCheckerFactoryBase.
    2. Перегружаем operator(). В операторе конструируем наш чекер через shared_ptr.
3. Регистрируем CheckerFactory в main().