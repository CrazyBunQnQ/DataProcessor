package com.crazybunqnq.dataprocessor.geo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Objects;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Geography {
    private String id;
    private String name;
    private String parentId;
    private String lat;
    private String lng;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Geography)) return false;
        Geography geography = (Geography) o;
        return Objects.equals(name, geography.name) && Objects.equals(parentId, geography.parentId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, parentId);
    }
}
