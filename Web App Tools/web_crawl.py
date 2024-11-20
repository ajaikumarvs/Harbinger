import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import networkx as nx
import plotly.graph_objects as go

# Function to get the base domain and subdomains
def get_domain_and_subdomains(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    subdomains = domain.split('.')
    subdomains = subdomains[:-2]  # Remove the last two parts (TLD + domain)
    return domain, subdomains

# Function to crawl a website and get links
def crawl_website(start_url, max_depth=3):
    visited_urls = set()
    url_queue = [(start_url, 0)]  # (url, depth)
    domain_graph = nx.Graph()

    while url_queue:
        url, depth = url_queue.pop(0)
        if depth > max_depth:
            continue

        if url in visited_urls:
            continue

        visited_urls.add(url)

        # Parse the base domain and subdomains
        domain, subdomains = get_domain_and_subdomains(url)

        # Add domain and subdomains to the graph
        domain_graph.add_node(domain)
        for sub in subdomains:
            subdomain = f"{sub}.{domain}"
            domain_graph.add_node(subdomain)
            domain_graph.add_edge(domain, subdomain)

        # Fetch the page and extract all links
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')

            # Find all links on the page
            for link in soup.find_all('a', href=True):
                new_url = link['href']
                new_url = urljoin(url, new_url)  # Resolve relative URLs
                new_domain, new_subdomains = get_domain_and_subdomains(new_url)

                if new_domain != domain:  # If it's a different domain, ignore for now
                    continue

                if new_url not in visited_urls:
                    url_queue.append((new_url, depth + 1))
        except requests.RequestException:
            continue

    return domain_graph

# Function to plot the graph as a network diagram
def plot_graph(domain_graph):
    # Create a layout for the graph
    pos = nx.spring_layout(domain_graph, k=0.3, iterations=50)

    # Generate plotly graph object
    edge_x = []
    edge_y = []
    for edge in domain_graph.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.append(x0)
        edge_x.append(x1)
        edge_y.append(y0)
        edge_y.append(y1)

    # Create the plotly figure
    fig = go.Figure(
        data=[
            go.Scatter(
                x=edge_x,
                y=edge_y,
                mode='lines',
                line=dict(width=0.5, color='gray'),
            ),
            go.Scatter(
                x=[pos[node][0] for node in domain_graph.nodes()],
                y=[pos[node][1] for node in domain_graph.nodes()],
                mode='markers+text',
                text=[node for node in domain_graph.nodes()],
                textposition="bottom center",
                marker=dict(color='red', size=10, opacity=0.7),
            ),
        ]
    )

    # Set the title and layout
    fig.update_layout(
        title="Domain and Subdomain Graph",
        title_x=0.5,
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False),
        yaxis=dict(showgrid=False, zeroline=False),
        plot_bgcolor='white'
    )

    # Save the figure as an HTML file
    fig.write_html("domain_subdomain_graph.html")

# Main function to run the crawler and plot the graph
def main():
    # Allow user to input the URL
    start_url = input("Enter the URL to crawl: ").strip()

    # Validate if the URL is valid
    if not start_url.startswith(('http://', 'https://')):
        print("Invalid URL. Please make sure it starts with 'http://' or 'https://'.")
        return

    print(f"Starting crawl on: {start_url}")
    graph = crawl_website(start_url)
    plot_graph(graph)
    print("Graph saved as 'domain_subdomain_graph.html'")

if __name__ == "__main__":
    main()
