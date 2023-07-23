defmodule DidServerWeb.ServiceJSON do
  def nodeinfo(%{links: links}) when is_map(links) do
    links
  end

  def nodeinfo_version(%{nodeinfo: nodeinfo}) when is_map(nodeinfo) do
    nodeinfo
  end
end
