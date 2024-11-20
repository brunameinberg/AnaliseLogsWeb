document.addEventListener("DOMContentLoaded", () => {
    const IPsPerPage = 5; // Quantidade de IPs visíveis por vez
    const ipSections = document.querySelectorAll(".attack-section");

    ipSections.forEach((section) => {
        const ipList = Array.from(section.querySelectorAll(".ip-item"));
        const loadMoreButton = section.querySelector(".load-more");

        let currentIndex = 0;

        // Oculta todos os IPs inicialmente
        ipList.forEach((ip) => (ip.style.display = "none"));

        // Função para exibir os próximos IPs
        const showNextIPs = () => {
            const nextIndex = Math.min(currentIndex + IPsPerPage, ipList.length);
            for (let i = currentIndex; i < nextIndex; i++) {
                ipList[i].style.display = "block";
            }
            currentIndex = nextIndex;

            // Se todos os IPs foram exibidos, esconder o botão
            if (currentIndex >= ipList.length) {
                loadMoreButton.style.display = "none";
            }
        };

        // Exibe os primeiros IPs ao carregar a página
        showNextIPs();

        // Evento no botão "Carregar mais"
        loadMoreButton.addEventListener("click", showNextIPs);
    });

    // Lógica para exibir/ocultar detalhes de cada IP
    document.querySelectorAll(".show-details").forEach((button) => {
        button.addEventListener("click", (event) => {
            const detailsDiv = event.target.nextElementSibling;

            if (detailsDiv.style.display === "none" || !detailsDiv.style.display) {
                detailsDiv.style.display = "block";
                event.target.textContent = "[Ocultar detalhes]";
            } else {
                detailsDiv.style.display = "none";
                event.target.textContent = "[Exibir detalhes]";
            }
        });
    });
});
