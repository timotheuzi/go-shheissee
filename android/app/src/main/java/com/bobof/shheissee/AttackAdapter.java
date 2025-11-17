package com.bobof.shheissee;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import java.util.ArrayList;
import java.util.List;

public class AttackAdapter extends RecyclerView.Adapter<AttackAdapter.AttackViewHolder> {

    private List<Attack> attacks = new ArrayList<>();

    @NonNull
    @Override
    public AttackViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_attack, parent, false);
        return new AttackViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull AttackViewHolder holder, int position) {
        Attack attack = attacks.get(position);
        holder.typeText.setText(attack.getType());
        holder.descriptionText.setText(attack.getDescription());
        holder.timestampText.setText(attack.getTimestamp());
    }

    @Override
    public int getItemCount() {
        return attacks.size();
    }

    public void setAttacks(List<Attack> attacks) {
        this.attacks = attacks;
        notifyDataSetChanged();
    }

    static class AttackViewHolder extends RecyclerView.ViewHolder {
        TextView typeText;
        TextView descriptionText;
        TextView timestampText;

        public AttackViewHolder(@NonNull View itemView) {
            super(itemView);
            typeText = itemView.findViewById(R.id.attack_type);
            descriptionText = itemView.findViewById(R.id.attack_description);
            timestampText = itemView.findViewById(R.id.attack_timestamp);
        }
    }
}
